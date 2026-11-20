package v017

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
)

const (
	// DefaultInFlight is PullOptions.InFlight when it is 0.
	DefaultInFlight = 3
	// MaxInFlight is the largest PullOptions.InFlight.
	MaxInFlight = 8
)

const (
	// readAhead bounds the bytes of answers a pull holds that are received and not yet stored, whatever InFlight is.
	// One answer is always admitted, so a single 4 MiB answer is held as before.
	readAhead = 6 << 20
	// commitBatch is the bytes of answers after which one commit stops taking more; it always takes one answer.
	commitBatch = 4 << 20
)

// errStopped ends the reader when the pull is aborted.
var errStopped = errors.New("kolosync: pull stopped")

// gate admits n more bytes when none are held or the total stays within limit.
type gate struct {
	mu    sync.Mutex
	held  int
	limit int
	wake  chan struct{}
}

func newGate(limit int) *gate { return &gate{limit: limit, wake: make(chan struct{}, 1)} }

// acquire waits for room for n bytes; it returns false if stop is closed first.
func (g *gate) acquire(n int, stop <-chan struct{}) bool {
	for {
		g.mu.Lock()
		if g.held == 0 || g.held+n <= g.limit {
			g.held += n
			g.mu.Unlock()
			return true
		}
		g.mu.Unlock()
		select {
		case <-g.wake:
		case <-stop:
			return false
		}
	}
}

func (g *gate) release(n int) {
	g.mu.Lock()
	g.held -= n
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// answer is one ENTRIES answer the reader hands to the committer, or, with typ 0, the error that ends the answers.
type answer struct {
	start  uint64
	m      message
	n      int                      // bytes held in the gate
	proof  kololog.ConsistencyProof // from the end of m's entries to the head, if proved
	proved bool
	err    error // after the checks of m, if it has any, the error that ends the pull
	e      []kololog.Entry
	done   bool // released
}

// pipe reads the answers of a fill ahead of the committer, over the stream of the client, which it owns until it ends.
// Answers come in the order the requests were sent, so each one starts where the one before it ended: the reader learns
// that end from the count at the start of the answer, and asks for the proof of that end and for the next range before
// the rest of the answer arrives.
type pipe struct {
	c     *client
	size  uint64
	slots chan struct{} // a token for each request whose answer is not stored yet
	mem   *gate
	out   chan *answer
	done  chan struct{} // closed by abort
	quiet chan struct{} // closed by drain, and by abort
	once  [2]sync.Once
}

func (c *client) newPipe(size, from uint64) *pipe {
	p := &pipe{
		c:     c,
		size:  size,
		slots: make(chan struct{}, c.depth),
		mem:   newGate(readAhead),
		out:   make(chan *answer, MaxInFlight+1),
		done:  make(chan struct{}),
		quiet: make(chan struct{}),
	}
	go p.run(from)
	return p
}

func (p *pipe) isQuiet() bool {
	select {
	case <-p.quiet:
		return true
	default:
		return false
	}
}

// take waits for a request slot; it returns false once the pipe is quiet or aborted.
func (p *pipe) take() bool {
	if p.isQuiet() {
		return false
	}
	select {
	case p.slots <- struct{}{}:
		return true
	case <-p.quiet:
		return false
	}
}

func (p *pipe) tryTake() bool {
	select {
	case p.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *pipe) request(start uint64) message {
	return message{typ: tEntriesReq, a: start, b: p.size - 1, keys: p.c.keys}
}

// deliver hands it to the committer; it returns false if the pull was aborted.
func (p *pipe) deliver(it *answer) bool {
	select {
	case p.out <- it:
		return true
	case <-p.done:
		p.release(it)
		return false
	}
}

func (p *pipe) fail(err error) {
	if !errors.Is(err, errStopped) {
		p.deliver(&answer{err: err, done: true})
	}
}

// release frees the slot and the bytes of each answer, once, and clears its keys.
func (p *pipe) release(items ...*answer) {
	for _, it := range items {
		if it.done {
			continue
		}
		it.done = true
		wipe(it.m)
		if it.m.typ != 0 {
			<-p.slots
			p.mem.release(it.n)
		}
	}
}

// run reads the answers from next on, until the head is reached, an error, or the pipe is quiet or aborted.
func (p *pipe) run(next uint64) {
	defer close(p.out)
	c := p.c
	chained := false // the request for next is sent
	for next < p.size {
		if !chained {
			if !p.take() {
				return
			}
			if _, err := writeMsg(c.st, p.request(next)); err != nil {
				p.fail(err)
				return
			}
		}
		if p.isQuiet() {
			_ = discardMsg(c.st) // the stream is the caller's again after the owed answers
			return
		}
		it, ch, err := p.read(next)
		if err != nil {
			p.fail(err)
			return
		}
		chained = ch
		if !p.deliver(it) || it.err != nil {
			return
		}
		k := uint64(len(it.m.entries))
		if k == 0 || k > p.size-next {
			return // the committer reports it
		}
		next += k
	}
}

// receive reads one answer, which the gate holds the bytes of while it is read, and returns them as held. If the pipe goes
// quiet while it waits for room, the answer is dropped and errStopped returned, with the stream after it.
func (p *pipe) receive(peek func(n int, b []byte) error) (m message, held int, err error) {
	frame := 0
	m, err = readAnswer(p.c.st, frameHooks{
		size: func(n int) error {
			frame = n
			if !p.mem.acquire(n, p.quiet) {
				return errStopped
			}
			held = n
			return nil
		},
		peek: peek,
	})
	if err != nil {
		if held > 0 {
			p.mem.release(held)
		}
		if errors.Is(err, errStopped) {
			_, _ = io.CopyN(io.Discard, p.c.st, int64(frame))
		}
		return message{}, 0, err
	}
	return m, held, nil
}

// read reads the answer to the request for next, and the proof it asked for. Once the count is known it asks for the
// proof of the answer's end, and for the next range if a slot is free.
func (p *pipe) read(next uint64) (it *answer, chained bool, err error) {
	c := p.c
	var asked bool
	m, held, err := p.receive(func(n int, b []byte) error {
		cnt, ok := entriesCount(b)
		if !ok || cnt == 0 || cnt > p.size-next || cnt > uint64(n/(minSigned+4)) || next+cnt == p.size || p.isQuiet() {
			return nil
		}
		end := next + cnt
		// A failed write ends the answer's proof or the next request; the answer itself is still read, and the stream's
		// error comes up at the next write or read.
		if _, err := writeMsg(c.st, message{typ: tProofReq, a: end, b: p.size}); err != nil {
			return nil
		}
		asked = true
		if p.tryTake() {
			if _, err := writeMsg(c.st, p.request(end)); err != nil {
				<-p.slots
				return nil
			}
			chained = true
		}
		return nil
	})
	if err == nil {
		m, err = checkAnswer(m, tEntries)
		if err != nil {
			p.mem.release(held)
		}
	}
	if err != nil {
		return nil, chained, err
	}
	it = &answer{start: next, m: m, n: held}
	if asked {
		it.proof, it.err = p.readProof()
		it.proved = it.err == nil
	}
	return it, chained, nil
}

// readProof reads the answer to a PROOF request.
func (p *pipe) readProof() (kololog.ConsistencyProof, error) {
	m, held, err := p.receive(nil)
	if err == nil {
		p.mem.release(held)
		m, err = checkAnswer(m, tProof)
	}
	if err != nil {
		return kololog.ConsistencyProof{}, err
	}
	pr, err := kololog.DecodeConsistencyProof(m.proof)
	if err != nil {
		return kololog.ConsistencyProof{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return pr, nil
}

// drain stops new requests and waits for the answers already asked for, so that the stream can be used for calls again.
func (p *pipe) drain() {
	p.once[0].Do(func() { close(p.quiet) })
	for it := range p.out {
		p.release(it)
	}
}

// abort ends the reader and the stream, which is not used again.
func (p *pipe) abort() {
	p.once[1].Do(func() {
		close(p.done)
		p.once[0].Do(func() { close(p.quiet) })
		_ = p.c.st.CancelRead(0)
		_ = p.c.st.CancelWrite(0)
	})
	for it := range p.out {
		p.release(it)
	}
}

// fill gets the entries from Len up to size, the size of h, with up to c.depth answers asked for at once: the reader
// takes them off the stream while this goroutine verifies and stores them, in order, in as few commits as the answers
// that are waiting allow.
func (c *client) fill(rep *kolostore.Replica, h kololog.Head, size uint64) (err error) {
	if rep.Len() >= size {
		return nil
	}
	p := c.newPipe(size, rep.Len())
	defer func() {
		if err != nil {
			p.abort()
		}
	}()
	for {
		first, ok := <-p.out
		if !ok {
			return nil
		}
		var items []*answer
		var tail error
		marked := false
		held := 0
		for it := first; it != nil; it = more(p) {
			if it.m.typ == 0 {
				tail = it.err
				break
			}
			e, mk, err := c.vet(it, size)
			if err == nil && !mk {
				err = it.err
			}
			if err == nil && mk && len(e) == 0 {
				err = markedAt(it.start)
			}
			if err != nil {
				p.release(it)
				tail = err
				break
			}
			it.e, it.proved = e, it.proved && len(e) == len(it.m.entries)
			items = append(items, it)
			held += it.n
			if mk {
				marked = true
				break
			}
			if held >= commitBatch {
				break
			}
		}
		if len(items) > 0 {
			err := c.store(rep, p, h, items, size)
			p.release(items...)
			if err != nil {
				return err
			}
			if marked {
				last := items[len(items)-1]
				return markedAt(last.start + uint64(len(last.e)))
			}
		}
		if tail != nil {
			return tail
		}
	}
}

// more returns the next answer if the reader has one ready.
func more(p *pipe) *answer {
	select {
	case it := <-p.out:
		return it
	default:
		return nil
	}
}

// vet checks the answer it against the request: no keys it did not ask for, at least one entry and not more than asked.
// With NoMarkers it returns the entries before the first marker and marked set.
func (c *client) vet(it *answer, size uint64) (entries []kololog.Entry, marked bool, err error) {
	if err := unasked(it.m, c.keys); err != nil {
		return nil, false, err
	}
	k, asked := uint64(len(it.m.entries)), size-it.start
	if k == 0 || k > asked {
		return nil, false, fmt.Errorf("%w: %d entries for %d asked", ErrProtocol, k, asked)
	}
	entries = it.m.entries
	if c.noMarkers {
		if j := slices.IndexFunc(entries, func(e kololog.Entry) bool { return len(e.Marker) != 0 }); j >= 0 {
			return entries[:j], true, nil
		}
	}
	return entries, false, nil
}

// endProof returns the proof that the entries of it lead to the head of size entries, asking the peer for it if the
// reader did not, as for the entries before a marker.
func (c *client) endProof(p *pipe, it *answer, size uint64) (kololog.ConsistencyProof, error) {
	end := it.start + uint64(len(it.e))
	switch {
	case end == size:
		return kololog.ConsistencyProof{OldSize: size, NewSize: size}, nil
	case it.proved:
		return it.proof, nil
	}
	p.drain()
	pr, err := c.proof(end, size)
	if err == nil {
		it.proof, it.proved = pr, true
	}
	return pr, err
}

// store commits the answers items, which follow one another, in one Update, or one by one if that fails, so that an error and
// the entries stored before it are the same as when each answer is stored alone.
func (c *client) store(rep *kolostore.Replica, p *pipe, h kololog.Head, items []*answer, size uint64) error {
	pr, perr := c.endProof(p, items[len(items)-1], size)
	var err error
	if perr == nil {
		entries := items[0].e
		if len(items) > 1 {
			entries = nil
			for _, it := range items {
				entries = append(entries, it.e...)
			}
		}
		if err = rep.Update(h, pr, entries); err == nil {
			return nil
		}
	}
	if len(items) > 1 {
		for _, it := range items {
			if err := c.store(rep, p, h, []*answer{it}, size); err != nil {
				return err
			}
		}
		return nil
	}
	if perr != nil {
		return perr
	}
	if errors.Is(err, kololog.ErrBadProof) {
		// The entries held before this answer may belong to another history than the peer's head.
		p.drain()
		return c.diverged(rep, items[0].start, err)
	}
	return checked(err)
}
