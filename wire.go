package kolosync

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	kololog "github.com/ciranda-dev/kolo-log"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

const (
	// MaxMessageSize is the largest message, length prefix excluded, that a peer sends or accepts.
	MaxMessageSize = 4 << 20
	// MaxStreams is how many streams Serve handles at once per connection; more are answered busy.
	MaxStreams = 16
	// Timeout bounds opening a stream, the wait for the next request, the start of each message read, and each
	// MinProgress bytes of a message read after that: a slow message that keeps moving is not cut off, one that stops is.
	// A message written may take Timeout plus its size at 500 bytes a second.
	Timeout = 60 * time.Second
	// MinProgress is the bytes of a message that must be read or written within every Timeout once it has begun, so
	// the slowest a message may move is 16 KiB a minute, about 273 bytes a second.
	MinProgress = 16 << 10
)

// writeMinRate is the slowest average, in bytes a second, at which a whole message may be written: the server holds an
// answer until it is written. Tests raise it.
var writeMinRate = 500

// timeout is Timeout; tests shorten it in TestMain, before any goroutine runs.
var timeout = Timeout

const (
	version   = 1
	maxSmall  = 4 << 10 // head, header, record, marker or proof encoding, and the bound of a request
	minSigned = 128     // a signed kolo-log record or marker holds at least a key, a log ID and a signature
	keySize   = 32
	overhead  = 32                         // upper bound of a message's header fields, or of one item's
	maxScan   = MaxMessageSize / minSigned // entries one STATE answer looks at: as many as one ENTRIES answer can hold

	// maxWatchItems is the most logs in one WATCH_REQ: the request bound (maxSmall) less its version, type and count
	// bytes, over the largest item, two keys and a 10-byte uvarint.
	maxWatchItems = (maxSmall - 3) / (keySize + kololog.LogIDSize + binary.MaxVarintLen64)
)

const (
	tHeadReq = 1 + iota
	tProofReq
	tEntriesReq
	tStateReq
	tHead
	tProof
	tEntries
	tState
	tError
	tFetchReq
	tFetch
	tStreamReq
	tCreditReq
	tWatchReq
	tWatch
)

const (
	codeNotFound = 1 + iota
	codeBusy
	codeTooLarge
	codeProtocol
)

// message is one decoded message; only the fields of its type are set.
type message struct {
	typ     uint64
	owner   [keySize]byte   // tHeadReq: the log owner's public key
	logID   kololog.LogID   // tHeadReq
	a, b    uint64          // first and second, start and end, or next (tState)
	size    uint64          // tFetchReq: the tree size of the inclusion proofs; tStreamReq: the size of the head to fill to
	keys    bool            // tEntriesReq, tStateReq, tStreamReq
	head    []byte          // tHead
	header  []byte          // tHead
	proof   []byte          // tProof
	entries []kololog.Entry // tEntries, tFetch
	proofs  [][]byte        // tFetch: the inclusion proof of each entry
	items   []item          // tState
	code    uint64          // tError
	credit  uint64          // tStreamReq, tCreditReq: bytes of ENTRIES answers the peer may send
	watch   []watchItem     // tWatchReq
	heads   [][]byte        // tWatch: encoded heads
}

// watchItem is a log named in WATCH_REQ and the length the watcher holds of it.
type watchItem struct {
	owner [keySize]byte
	logID kololog.LogID
	held  uint64
}

// item is a delete marker or an entry key for one index.
type item struct {
	index  uint64
	marker []byte
	key    []byte
}

// encode returns the payload of m.
func encode(m message) []byte { return frameOf(m)[4:] }

// frameOf returns m with its length prefix, built in one presized slice so that clearing it clears every copy of the
// entry keys it holds; kolo-codec's Encoder would leave copies behind as it grows. The bytes are the same.
func frameOf(m message) []byte {
	b := make([]byte, 4, 4+bound(m))
	b = binary.AppendUvarint(b, version)
	b = binary.AppendUvarint(b, m.typ)
	switch m.typ {
	case tHeadReq:
		b = append(append(b, m.owner[:]...), m.logID[:]...)
	case tProofReq:
		b = binary.AppendUvarint(b, m.a)
		b = binary.AppendUvarint(b, m.b)
	case tEntriesReq, tStateReq:
		b = binary.AppendUvarint(b, m.a)
		b = binary.AppendUvarint(b, m.b)
		if m.keys {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	case tFetchReq:
		b = binary.AppendUvarint(b, m.a)
		b = binary.AppendUvarint(b, m.b)
		b = binary.AppendUvarint(b, m.size)
	case tStreamReq:
		b = binary.AppendUvarint(b, m.a)
		b = binary.AppendUvarint(b, m.size)
		if m.keys {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
		b = binary.AppendUvarint(b, m.credit)
	case tCreditReq:
		b = binary.AppendUvarint(b, m.credit)
	case tWatchReq:
		b = binary.AppendUvarint(b, uint64(len(m.watch)))
		for _, it := range m.watch {
			b = append(append(b, it.owner[:]...), it.logID[:]...)
			b = binary.AppendUvarint(b, it.held)
		}
	case tWatch:
		b = binary.AppendUvarint(b, uint64(len(m.heads)))
		for _, h := range m.heads {
			b = putBytes(b, h)
		}
	case tHead:
		b = putBytes(putBytes(b, m.head), m.header)
	case tProof:
		b = putBytes(b, m.proof)
	case tEntries, tFetch:
		b = binary.AppendUvarint(b, uint64(len(m.entries)))
		for i, x := range m.entries {
			b = putBytes(putBytes(putBytes(putBytes(b, x.Record), x.Ciphertext), x.Marker), x.Key)
			if m.typ == tFetch {
				b = putBytes(b, m.proofs[i])
			}
		}
	case tState:
		b = binary.AppendUvarint(b, m.a)
		b = binary.AppendUvarint(b, uint64(len(m.items)))
		for _, it := range m.items {
			b = binary.AppendUvarint(b, it.index)
			if it.marker != nil {
				b = putBytes(append(b, 0), it.marker)
			} else {
				b = putBytes(append(b, 1), it.key)
			}
		}
	case tError:
		b = binary.AppendUvarint(b, m.code)
	}
	binary.LittleEndian.PutUint32(b, uint32(len(b)-4))
	return b
}

// putBytes appends x with its uvarint length, as kolo-codec's PutBytes.
func putBytes(b, x []byte) []byte {
	return append(binary.AppendUvarint(b, uint64(len(x))), x...)
}

// bound is at least the payload size of m.
func bound(m message) int {
	n := 4*binary.MaxVarintLen64 + kololog.LogIDSize + 1 + blen(m.head) + blen(m.header) + blen(m.proof)
	for _, e := range m.entries {
		n += entrySize(e)
	}
	for _, p := range m.proofs {
		n += blen(p)
	}
	for _, it := range m.items {
		n += overhead + blen(it.marker) + blen(it.key)
	}
	n += len(m.watch) * (keySize + kololog.LogIDSize + binary.MaxVarintLen64)
	for _, h := range m.heads {
		n += blen(h)
	}
	return n
}

var errMalformed = fmt.Errorf("%w: malformed message", ErrProtocol)

// decode parses one request, or one answer if requests is false, and accepts only its canonical encoding.
// The type is checked before the body, so a server never decodes an answer's entries.
func decode(b []byte, requests bool) (message, error) {
	m, err := decodeFields(kolocodec.NewDecoder(b), requests)
	if err != nil {
		return message{}, errMalformed
	}
	return m, nil
}

func decodeFields(d *kolocodec.Decoder, requests bool) (m message, err error) {
	v, err := d.Uvarint()
	if err != nil {
		return m, err
	}
	if v != version {
		return m, errors.New("version")
	}
	if m.typ, err = d.Uvarint(); err != nil {
		return m, err
	}
	if request(m.typ) != requests {
		return m, errors.New("direction")
	}
	switch m.typ {
	case tHeadReq:
		var owner, id []byte
		if owner, err = d.Fixed(keySize); err == nil {
			copy(m.owner[:], owner)
			if id, err = d.Fixed(kololog.LogIDSize); err == nil {
				copy(m.logID[:], id)
			}
		}
	case tProofReq:
		if m.a, err = d.Uvarint(); err == nil {
			m.b, err = d.Uvarint()
		}
	case tEntriesReq, tStateReq:
		if m.a, err = d.Uvarint(); err == nil {
			if m.b, err = d.Uvarint(); err == nil {
				m.keys, err = d.Bool()
			}
		}
	case tFetchReq:
		if m.a, err = d.Uvarint(); err == nil {
			if m.b, err = d.Uvarint(); err == nil {
				m.size, err = d.Uvarint()
			}
		}
	case tStreamReq:
		if m.a, err = d.Uvarint(); err == nil {
			if m.size, err = d.Uvarint(); err == nil {
				if m.keys, err = d.Bool(); err == nil {
					m.credit, err = d.Uvarint()
				}
			}
		}
	case tCreditReq:
		m.credit, err = d.Uvarint()
	case tWatchReq:
		m.watch, err = decodeWatchReq(d)
	case tWatch:
		m.heads, err = decodeHeads(d)
	case tHead:
		if m.head, err = d.Bytes(maxSmall); err == nil {
			m.header, err = d.Bytes(maxSmall)
		}
	case tProof:
		m.proof, err = d.Bytes(maxSmall)
	case tEntries, tFetch:
		m.entries, m.proofs, err = decodeEntries(d, m.typ == tFetch)
		defer func() {
			if err != nil {
				wipe(m)
			}
		}()
	case tState:
		if m.a, err = d.Uvarint(); err == nil {
			m.items, err = decodeItems(d)
		}
		defer func() {
			if err != nil {
				wipe(m)
			}
		}()
	case tError:
		if m.code, err = d.Uvarint(); err == nil && (m.code < codeNotFound || m.code > codeProtocol) {
			err = errors.New("code")
		}
	default:
		err = errors.New("type")
	}
	if err != nil {
		return m, err
	}
	return m, d.Done()
}

// decodeEntries decodes the entries of ENTRIES, or of FETCH with the inclusion proof after each entry if proofs is set.
func decodeEntries(d *kolocodec.Decoder, proofs bool) (out []kololog.Entry, ps [][]byte, err error) {
	n, err := d.UvarintMax(uint64(d.Len() / (minSigned + 4)))
	if err != nil {
		return nil, nil, err
	}
	out = make([]kololog.Entry, 0, n)
	if proofs {
		ps = make([][]byte, 0, n)
	}
	defer func() {
		if err != nil {
			wipe(message{entries: out})
		}
	}()
	for range n {
		var e kololog.Entry
		if e.Record, err = d.Bytes(maxSmall); err != nil {
			return out, ps, err
		}
		if e.Ciphertext, err = d.Bytes(MaxMessageSize); err != nil {
			return out, ps, err
		}
		if e.Marker, err = d.Bytes(maxSmall); err != nil {
			return out, ps, err
		}
		if e.Key, err = d.Bytes(keySize); err != nil {
			return out, ps, err
		}
		out = append(out, e)
		if len(e.Record) < minSigned || (len(e.Marker) != 0 && len(e.Marker) < minSigned) || (len(e.Key) != 0 && len(e.Key) != keySize) {
			return out, ps, errors.New("field size")
		}
		if proofs {
			var p []byte
			if p, err = d.Bytes(maxSmall); err != nil {
				return out, ps, err
			}
			ps = append(ps, p)
		}
	}
	return out, ps, nil
}

// decodeWatchReq decodes the one to maxWatchItems logs of WATCH_REQ.
func decodeWatchReq(d *kolocodec.Decoder) ([]watchItem, error) {
	n, err := d.UvarintMax(min(maxWatchItems, uint64(d.Len()/(keySize+kololog.LogIDSize+1))))
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("no logs")
	}
	out := make([]watchItem, n)
	for i := range out {
		owner, err := d.Fixed(keySize)
		if err != nil {
			return nil, err
		}
		id, err := d.Fixed(kololog.LogIDSize)
		if err != nil {
			return nil, err
		}
		copy(out[i].owner[:], owner)
		copy(out[i].logID[:], id)
		if out[i].held, err = d.Uvarint(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// decodeHeads decodes the heads of WATCH, each between minSigned and maxSmall bytes.
func decodeHeads(d *kolocodec.Decoder) ([][]byte, error) {
	n, err := d.UvarintMax(uint64(d.Len() / (minSigned + 2)))
	if err != nil || n == 0 {
		return nil, err
	}
	out := make([][]byte, n)
	for i := range out {
		if out[i], err = d.Bytes(maxSmall); err != nil {
			return nil, err
		}
		if len(out[i]) < minSigned {
			return nil, errors.New("head size")
		}
	}
	return out, nil
}

// request reports whether t is a request type, which only a server accepts.
func request(t uint64) bool {
	return t < tHead || t == tFetchReq || t == tStreamReq || t == tCreditReq || t == tWatchReq
}

func decodeItems(d *kolocodec.Decoder) (out []item, err error) {
	n, err := d.UvarintMax(uint64(d.Len() / (keySize + 3)))
	if err != nil {
		return nil, err
	}
	out = make([]item, 0, n)
	defer func() {
		if err != nil {
			wipe(message{items: out})
		}
	}()
	for i := range n {
		var it item
		if it.index, err = d.Uvarint(); err != nil {
			return out, err
		}
		if i > 0 && it.index <= out[i-1].index {
			return out, errors.New("order")
		}
		kind, err := d.Uvarint()
		if err != nil {
			return out, err
		}
		switch kind {
		case 0:
			if it.marker, err = d.Bytes(maxSmall); err == nil && len(it.marker) < minSigned {
				err = errors.New("marker size")
			}
		case 1:
			if it.key, err = d.Bytes(keySize); err == nil && len(it.key) != keySize {
				err = errors.New("key size")
			}
		default:
			err = errors.New("kind")
		}
		out = append(out, it)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// frameSize reads a length prefix and checks it before anything is allocated.
func frameSize(h [4]byte) (int, error) {
	n := binary.LittleEndian.Uint32(h[:])
	if n == 0 {
		return 0, errMalformed
	}
	if n > MaxMessageSize {
		return 0, fmt.Errorf("%w: message of %d bytes", ErrTooLarge, n)
	}
	return int(n), nil
}

// readFrame reads one frame from r; after its length is known and checked, grow, if not nil, is called with it.
func readFrame(r io.Reader, requests bool, grow func(int)) (message, error) {
	var h frameHooks
	if grow != nil {
		h.size = func(n int) error { grow(n); return nil }
	}
	return readFrameWith(r, requests, h)
}

// frameHooks are called while a frame is read; a hook that returns an error ends the read with it.
type frameHooks struct {
	size func(n int) error           // the length n is known and checked, before the body is allocated
	peek func(n int, b []byte) error // the first bytes of a body of n bytes, before the rest is read
	got  func(n int)                 // readAnswer only: n more bytes of the body were read
}

// peekSize is enough bytes for the version, the type and a count.
const peekSize = 3 * binary.MaxVarintLen64

func readFrameWith(r io.Reader, requests bool, hooks frameHooks) (message, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return message{}, ioErr(err)
	}
	n, err := frameSize(h)
	if err != nil {
		return message{}, err
	}
	if requests && n > maxSmall {
		return message{}, fmt.Errorf("%w: request of %d bytes", ErrTooLarge, n)
	}
	if hooks.size != nil {
		if err := hooks.size(n); err != nil {
			return message{}, err
		}
	}
	b := make([]byte, n)
	defer clear(b) // may hold entry keys
	rest := b
	if hooks.peek != nil {
		first := b[:min(n, peekSize)]
		if _, err := io.ReadFull(r, first); err != nil {
			return message{}, ioErr(err)
		}
		if err := hooks.peek(n, first); err != nil {
			return message{}, err
		}
		rest = b[len(first):]
	}
	if _, err := io.ReadFull(r, rest); err != nil {
		return message{}, ioErr(err)
	}
	return decode(b, requests)
}

// entriesCount returns the entry count that an ENTRIES answer's payload b starts with, without checking the rest.
func entriesCount(b []byte) (uint64, bool) {
	v, n := binary.Uvarint(b)
	if n <= 0 || v != version {
		return 0, false
	}
	b = b[n:]
	t, n := binary.Uvarint(b)
	if n <= 0 || t != tEntries {
		return 0, false
	}
	c, n := binary.Uvarint(b[n:])
	return c, n > 0
}

// paced reads from st and starts a new deadline of timeout at the first read after each MinProgress bytes, at most
// once every eighth of the timeout, which keeps the calls to the transport few on a fast path. got, if not nil, is told
// the bytes read in steps of at least MinProgress, and the rest at flush.
type paced struct {
	st     *kolotransport.Stream
	left   int       // bytes still to come before the deadline may move
	set    time.Time // when the deadline was set last, zero to set one at the next read
	got    func(n int)
	unsent int
}

// restart makes the next read start a new deadline.
func (p *paced) restart() { p.left, p.set = 0, time.Time{} }

func (p *paced) Read(b []byte) (int, error) {
	if p.left <= 0 {
		if now := time.Now(); p.set.IsZero() || now.Sub(p.set) >= timeout/8 {
			if err := p.st.SetReadDeadline(now.Add(timeout)); err != nil {
				return 0, err
			}
			p.left, p.set = MinProgress, now
		}
	}
	n, err := p.st.Read(b)
	p.left -= n
	if p.got != nil {
		if p.unsent += n; p.unsent >= MinProgress {
			p.flush()
		}
	}
	return n, err
}

func (p *paced) flush() {
	if p.got != nil && p.unsent > 0 {
		p.got(p.unsent)
	}
	p.unsent = 0
}

// readAnswer reads one answer, like readMsg, and calls hooks on the way.
func readAnswer(st *kolotransport.Stream, hooks frameHooks) (message, error) {
	r := &paced{st: st}
	size := hooks.size
	hooks.size = func(n int) error {
		var err error
		if size != nil {
			err = size(n)
		}
		// The wait for memory in size is not the peer's time, so the body's deadline starts after it.
		r.restart()
		r.got = hooks.got
		return err
	}
	if peek := hooks.peek; peek != nil {
		hooks.peek = func(n int, b []byte) error {
			err := peek(n, b)
			r.restart() // the writes in peek are not the peer's time either
			return err
		}
	}
	m, err := readFrameWith(r, false, hooks)
	r.flush()
	return m, err
}

// readMsg reads one length-prefixed request, or answer if requests is false: its length within timeout, then each
// MinProgress bytes of its body within timeout.
func readMsg(st *kolotransport.Stream, requests bool) (message, error) {
	r := &paced{st: st}
	return readFrame(r, requests, func(int) { r.restart() })
}

// readWatchMsg reads one request on a watch stream, which is idle by design: it waits for the first byte with no
// deadline, then reads the message as readMsg does.
func readWatchMsg(st *kolotransport.Stream) (message, error) {
	_ = st.SetReadDeadline(time.Time{})
	var b [1]byte
	if _, err := io.ReadFull(st, b[:]); err != nil {
		return message{}, ioErr(err)
	}
	r := &paced{st: st}
	return readFrame(io.MultiReader(bytes.NewReader(b[:]), r), true, func(int) { r.restart() })
}

// discardMsg reads and drops one message, with the deadlines of readMsg; it checks only the length.
func discardMsg(st *kolotransport.Stream) error {
	r := &paced{st: st}
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return ioErr(err)
	}
	n, err := frameSize(h)
	if err != nil {
		return err
	}
	r.restart()
	_, err = io.CopyN(io.Discard, r, int64(n))
	return ioErr(err)
}

// writeMsg writes one length-prefixed message within timeout plus its size at writeMinRate: a reader that moves the
// message at least that fast is served however slow its path, and one that barely reads cannot hold it for hours.
// It returns the bytes written, also on an error.
func writeMsg(st *kolotransport.Stream, m message) (int, error) {
	b := frameOf(m)
	defer clear(b)
	if len(b)-4 > MaxMessageSize {
		return 0, fmt.Errorf("%w: message of %d bytes", ErrTooLarge, len(b)-4)
	}
	if err := st.SetWriteDeadline(time.Now().Add(timeout + time.Duration(len(b))*time.Second/time.Duration(writeMinRate))); err != nil {
		return 0, ioErr(err)
	}
	n, err := st.Write(b)
	return n, ioErr(err)
}

// ioErr maps stream errors to the package's errors.
func ioErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%w: stream ended early", ErrProtocol)
	}
	return fmt.Errorf("kolosync: %w", err)
}

// blen is the encoded size of a length-prefixed byte string.
func blen(b []byte) int {
	return len(binary.AppendUvarint(nil, uint64(len(b)))) + len(b)
}

func entrySize(e kololog.Entry) int {
	return blen(e.Record) + blen(e.Ciphertext) + blen(e.Marker) + blen(e.Key)
}
