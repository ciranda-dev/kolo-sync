package kolosync

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

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
	// readAhead bounds the bytes of answers received and not yet stored, whatever InFlight is.
	// One answer is always admitted, so a single 4 MiB answer fits.
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
	meter *PullMeter // if not nil, told the bytes held and how long a wait for room took
}

func newGate(limit int) *gate { return &gate{limit: limit, wake: make(chan struct{}, 1)} }

// acquire waits for room for n bytes; it returns false if stop is closed first.
func (g *gate) acquire(n int, stop <-chan struct{}) bool {
	var since time.Time
	for {
		g.mu.Lock()
		if g.held == 0 || g.held+n <= g.limit {
			g.held += n
			held := g.held
			g.mu.Unlock()
			if g.meter != nil {
				var waited time.Duration
				if !since.IsZero() {
					waited = max(time.Since(since), 1)
				}
				g.meter.memory(held, waited)
			}
			return true
		}
		g.mu.Unlock()
		if since.IsZero() {
			since = time.Now()
		}
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

// errNoStream ends the first streamed answer of a peer that does not know STREAM_REQ.
var errNoStream = errors.New("kolosync: the peer does not stream")

// pipe reads the answers of a fill ahead of the committer, over the client's stream, which it owns until it ends.
// With a peer that streams, it sends STREAM_REQ and CREDIT_REQ and the peer answers while the credit lasts, each answer
// followed by the proof of its end. Otherwise answers come in request order: the reader learns where one ends from its
// count and asks for that proof and the next range before the rest of the answer arrives.
type pipe struct {
	c        *client
	size     uint64
	streamed bool
	slots    chan struct{} // a token for each request whose answer is not stored yet, if not streamed
	mem      *gate
	out      chan *answer
	done     chan struct{} // closed by abort
	quiet    chan struct{} // closed by drain, and by abort
	once     [2]sync.Once
	meter    *PullMeter
	sent     []time.Time // when each request whose answer has not started was written, if not streamed
	// Only the reader reads or writes the rest, which is for a streamed pipe.
	granted int64 // credit asked for, in bytes
	recv    int64 // bytes of answers read, which the peer counts against the credit
	pace    pace
	sentAt  time.Time // when STREAM_REQ was written, until the first answer starts
}

func (c *client) newPipe(size, from uint64) *pipe {
	p := &pipe{
		c:        c,
		size:     size,
		streamed: c.streamed,
		mem:      newGate(readAhead),
		out:      make(chan *answer, MaxInFlight+1),
		done:     make(chan struct{}),
		quiet:    make(chan struct{}),
		meter:    c.meter,
	}
	p.mem.meter = c.meter
	if p.streamed {
		p.pace = pace{maxReq: c.maxAhead}
		p.pace.sample(c.rtt)
		go p.runStream(from)
	} else {
		p.slots = make(chan struct{}, c.depth)
		go p.run(from)
	}
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
		p.meter.inFlight(len(p.slots))
		return true
	default:
	}
	p.meter.inFlightBlocked()
	select {
	case p.slots <- struct{}{}:
		p.meter.inFlight(len(p.slots))
		return true
	case <-p.quiet:
		return false
	}
}

func (p *pipe) tryTake() bool {
	select {
	case p.slots <- struct{}{}:
		p.meter.inFlight(len(p.slots))
		return true
	default:
		p.meter.inFlightBlocked()
		return false
	}
}

func (p *pipe) request(start uint64) message {
	return message{typ: tEntriesReq, a: start, b: p.size - 1, keys: p.c.keys}
}

// sendRequest writes the request for the entries from start, which the slot taken is for.
func (p *pipe) sendRequest(start uint64) error {
	if _, err := writeMsg(p.c.st, p.request(start)); err != nil {
		return err
	}
	p.sent = append(p.sent, time.Now())
	p.meter.requested()
	return nil
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
			if !p.streamed {
				<-p.slots
				p.meter.inFlight(len(p.slots))
			}
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
			if err := p.sendRequest(next); err != nil {
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

// runStream reads the answers of a stream from next on, until the head is reached, an error, or the pipe is quiet or
// aborted and the credit asked for is used up. Once quiet it reads what the peer still owes and drops it.
func (p *pipe) runStream(next uint64) {
	defer close(p.out)
	for next < p.size {
		if err := p.topUp(next); err != nil {
			p.fail(err)
			return
		}
		if p.recv >= p.granted {
			return // quiet, and nothing is owed
		}
		it, k, err := p.readChunk(next)
		if err != nil {
			p.fail(err)
			return
		}
		if it != nil {
			if !p.deliver(it) || (it.err != nil && !errors.Is(it.err, errStopped)) {
				return
			}
		}
		if k == 0 || k > p.size-next {
			return // the committer reports it
		}
		next += k
	}
}

// topUp asks for credit while less than the requests wanted are in flight, starting with STREAM_REQ for the entries from next.
func (p *pipe) topUp(next uint64) error {
	if p.isQuiet() {
		return nil
	}
	n, capped := p.pace.requests()
	for p.granted-p.recv <= int64(n-1)*requestCredit {
		m := message{typ: tCreditReq, credit: requestCredit}
		if p.granted == 0 {
			m = message{typ: tStreamReq, a: next, size: p.size, keys: p.c.keys, credit: requestCredit}
			p.sentAt = time.Now()
		}
		if _, err := writeMsg(p.c.st, m); err != nil {
			return err
		}
		p.granted += requestCredit
		p.meter.requested()
	}
	if capped {
		p.meter.inFlightBlocked()
	}
	p.inFlight()
	return nil
}

// inFlight tells the meter how many requests are not used up.
func (p *pipe) inFlight() {
	p.meter.inFlight(int(max(0, (p.granted-p.recv+requestCredit-1)/requestCredit)))
}

// receive reads one answer and returns the bytes the gate holds for it as held. If the pipe goes quiet while it waits
// for room, the answer is dropped and errStopped returned. entries is set for an ENTRIES answer, whose first bytes
// end the wait of the oldest request.
func (p *pipe) receive(entries bool, peek func(n int, b []byte) error) (m message, held int, err error) {
	frame := 0
	start := time.Now()
	var inHooks time.Duration
	var got func(int)
	if entries {
		got = p.meter.received
	}
	m, err = readAnswer(p.c.st, frameHooks{
		size: func(n int) error {
			t := time.Now()
			frame = n
			if entries && len(p.sent) > 0 {
				p.meter.firstByte(t.Sub(p.sent[0]))
				p.sent = p.sent[1:]
			}
			ok := p.mem.acquire(n, p.quiet)
			inHooks += time.Since(t)
			if !ok {
				return errStopped
			}
			held = n
			return nil
		},
		peek: peek,
		got:  got,
	})
	p.meter.readerWait(time.Since(start) - inHooks)
	if err != nil {
		if held > 0 {
			p.mem.release(held)
		}
		if errors.Is(err, errStopped) {
			_, _ = io.CopyN(io.Discard, &paced{st: p.c.st}, int64(frame))
		}
		return message{}, 0, err
	}
	return m, held, nil
}

// read reads the answer to the request for next, and the proof of its end, asked for once the count is known, along
// with the next range if a slot is free.
func (p *pipe) read(next uint64) (it *answer, chained bool, err error) {
	c := p.c
	var asked bool
	m, held, err := p.receive(true, func(n int, b []byte) error {
		cnt, ok := entriesCount(b)
		if !ok || cnt == 0 || cnt > p.size-next || cnt > uint64(n/(minSigned+4)) || next+cnt == p.size || p.isQuiet() {
			return nil
		}
		end := next + cnt
		// A failed write only loses the proof or the next request; the stream's error comes up at the next write or read.
		if _, err := writeMsg(c.st, message{typ: tProofReq, a: end, b: p.size}); err != nil {
			return nil
		}
		asked = true
		if p.tryTake() {
			if err := p.sendRequest(end); err != nil {
				<-p.slots
				p.meter.inFlight(len(p.slots))
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
	p.meter.answerRead(held, len(m.entries))
	it = &answer{start: next, m: m, n: held}
	if asked {
		it.proof, it.err = p.readProof()
		it.proved = it.err == nil
	}
	return it, chained, nil
}

// readChunk reads the answer that starts at next and, unless it reaches the head, the proof of its end. If the pipe is
// quiet it drops them and returns no answer. It also returns the number of entries the answer holds.
func (p *pipe) readChunk(next uint64) (it *answer, k uint64, err error) {
	c := p.c
	frame := 0
	held := 0
	dropped := false
	start := time.Now()
	var inHooks time.Duration
	m, err := readAnswer(c.st, frameHooks{size: func(n int) error {
		t := time.Now()
		frame = n
		if !p.sentAt.IsZero() {
			d := t.Sub(p.sentAt)
			p.meter.firstByte(d)
			p.pace.sample(d)
			p.sentAt = time.Time{}
		}
		p.recv += int64(n)
		_ = p.topUp(next) // a failed write comes up at the next one
		if p.isQuiet() || !p.mem.acquire(n, p.quiet) {
			dropped = true
			inHooks += time.Since(t)
			return errStopped
		}
		inHooks += time.Since(t)
		held = n
		return nil
	}, got: p.meter.received})
	p.meter.readerWait(time.Since(start) - inHooks)
	if dropped {
		k, err := p.drop(frame, next)
		return nil, k, err
	}
	if err == nil && !c.seen.Load() && m.typ == tError && m.code == codeProtocol {
		p.mem.release(held)
		return nil, 0, errNoStream
	}
	if err == nil {
		m, err = checkAnswer(m, tEntries)
	}
	if err != nil {
		if held > 0 {
			p.mem.release(held)
		}
		return nil, 0, err
	}
	if !c.seen.Swap(true) {
		p.meter.streamed()
	}
	k = uint64(len(m.entries))
	p.pace.arrived(time.Now(), frame)
	p.meter.answerRead(frame, int(k))
	it = &answer{start: next, m: m, n: held}
	if k > 0 && k <= p.size-next && k < p.size-next {
		it.proof, it.err = p.readProof()
		it.proved = it.err == nil
	}
	return it, k, nil
}

// drop reads and discards the rest of an answer of n bytes that starts at next, and the proof of its end. It returns the
// answer's entry count.
func (p *pipe) drop(n int, next uint64) (uint64, error) {
	r := &paced{st: p.c.st}
	b := make([]byte, min(n, peekSize))
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, ioErr(err)
	}
	k, ok := entriesCount(b)
	if !ok {
		return 0, fmt.Errorf("%w: unexpected message", ErrProtocol)
	}
	if _, err := io.CopyN(io.Discard, r, int64(n-len(b))); err != nil {
		return 0, ioErr(err)
	}
	if k > 0 && k < p.size-next {
		return k, discardMsg(p.c.st)
	}
	return k, nil
}

// readProof reads the answer to a PROOF request.
func (p *pipe) readProof() (kololog.ConsistencyProof, error) {
	m, held, err := p.receive(false, nil)
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

// fill gets the entries from Len up to size, the size of h, from a peer that streams, or else, with up to c.depth answers
// asked for at once, from one that does not.
func (c *client) fill(rep *kolostore.Replica, h kololog.Head, size uint64) error {
	err := c.fillFrom(rep, h, size)
	if !errors.Is(err, errNoStream) {
		return err
	}
	// A peer that does not know STREAM_REQ answers it with an error and ends the stream: ask on a new one.
	c.streamed = false
	if err := c.reopen(); err != nil {
		return err
	}
	return c.fillFrom(rep, h, size)
}

// fillFrom gets the entries from Len up to size, the size of h: the reader takes the answers off the stream while this
// goroutine verifies and stores them, in order, in as few commits as the answers that are waiting allow.
func (c *client) fillFrom(rep *kolostore.Replica, h kololog.Head, size uint64) (err error) {
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
		t0 := time.Now()
		first, ok := <-p.out
		t1 := time.Now()
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
				c.meter.committed(time.Since(t1), t1.Sub(t0))
				return err
			}
			if marked {
				last := items[len(items)-1]
				c.meter.committed(time.Since(t1), t1.Sub(t0))
				return markedAt(last.start + uint64(len(last.e)))
			}
		}
		c.meter.committed(time.Since(t1), t1.Sub(t0))
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

// store commits the consecutive answers items in one Update, or one by one if that fails, so an error and the entries
// stored before it are the same as when each answer is stored alone.
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
