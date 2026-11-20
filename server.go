package kolosync

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	kololog "github.com/ciranda-dev/kolo-log"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// Access is what a peer may pull from one offered log.
type Access int

const (
	// NoAccess gives the peer the same answer as a log we do not have.
	NoAccess Access = iota
	// Ciphertext gives records, proofs, ciphertexts and delete markers, but no entry keys.
	Ciphertext
	// Keys gives everything Ciphertext gives, and the entry keys.
	Keys
)

// Source is a log a Server can offer: a kolo-store Log or Replica, or a kolo-log Log or Replica.
type Source interface {
	ID() kololog.LogID
	Header() kololog.LogHeader
	Head() (kololog.Head, error)
	Record(index uint64) (kololog.Record, error)
	Entry(index uint64) (kololog.Entry, error)
	EntryInfo(index uint64) (kololog.EntryInfo, error)
	Key(index uint64) (kololog.EntryKey, error)
	InclusionProof(index, size uint64) (kololog.InclusionProof, error)
	ConsistencyProof(oldSize, newSize uint64) (kololog.ConsistencyProof, error)
}

// Server serves the logs the application offers to the peers it authorizes; it is safe for concurrent use.
// A log is named by its owner's key and its log ID, so two owners' logs with one ID are two logs.
type Server struct {
	authorize func(peer, owner ed25519.PublicKey, logID kololog.LogID) Access
	mu        sync.RWMutex
	logs      map[logName]Source
	sent      atomic.Uint64
	active    atomic.Int64
	limits    ServerOptions
	taken     atomic.Int64  // stream slots in use, over all connections
	held      atomic.Int64  // bytes reserved for answers that are built or being written
	refused   atomic.Uint64 // streams and answers refused because a server-wide limit was reached
}

const (
	// DefaultMaxTotalStreams is the default ServerOptions.MaxTotalStreams: 16 connections each serving MaxStreams streams.
	DefaultMaxTotalStreams = 16 * MaxStreams
	// DefaultMaxAnswerBytes is the default ServerOptions.MaxAnswerBytes, a quarter of kolo-transport's DefaultMaxMemory (1 GiB),
	// which leaves the rest of that budget to the connections themselves.
	DefaultMaxAnswerBytes = 256 << 20
)

// ServerOptions are the limits a Server applies over all the connections it serves, on top of MaxStreams for each.
// A zero field is its default. A stream or an answer over a limit is answered busy, which a Pull or Fetch returns as ErrBusy.
type ServerOptions struct {
	// MaxTotalStreams is the most streams served at once over all connections.
	MaxTotalStreams int
	// MaxAnswerBytes is the most memory the answers being built or written may hold at once; each answer counts twice its
	// size, the entries read from the log and the frame sent. At least 2 * MaxMessageSize, so one largest answer always fits.
	MaxAnswerBytes int64
}

// logName is a log's owner key and log ID.
type logName struct {
	owner [ed25519.PublicKeySize]byte
	id    kololog.LogID
}

func nameOf(owner ed25519.PublicKey, logID kololog.LogID) (logName, bool) {
	n := logName{id: logID}
	copy(n.owner[:], owner)
	return n, len(owner) == ed25519.PublicKeySize
}

// ServerStats are a Server's totals over all its connections.
type ServerStats struct {
	BytesSent      uint64 // frame bytes written, every answer included
	ActiveStreams  int    // streams being served now, refused ones not included
	RefusedByLimit uint64 // streams and answers refused because MaxTotalStreams or MaxAnswerBytes was reached
	AnswerBytes    int64  // memory the answers being built or written hold now, counted as MaxAnswerBytes counts it
}

// Stats returns the server's totals; it is safe to call at any time.
func (s *Server) Stats() ServerStats {
	return ServerStats{BytesSent: s.sent.Load(), ActiveStreams: int(s.active.Load()), RefusedByLimit: s.refused.Load(), AnswerBytes: s.held.Load()}
}

// write sends m and counts its bytes.
func (s *Server) write(st *kolotransport.Stream, m message) error {
	_, err := s.writeN(st, m)
	return err
}

// writeN is write that also returns the bytes written, length prefix included.
func (s *Server) writeN(st *kolotransport.Stream, m message) (int, error) {
	n, err := writeMsg(st, m)
	s.sent.Add(uint64(n))
	return n, err
}

// NewServer returns a Server with no offered logs. authorize is asked on every request, for any owner and log ID;
// nil, a panic or any other value than Ciphertext or Keys means NoAccess.
func NewServer(authorize func(peer, owner ed25519.PublicKey, logID kololog.LogID) Access) *Server {
	s, _ := NewServerWith(authorize, nil)
	return s
}

// NewServerWith is NewServer with the server-wide limits of opts; nil is all defaults.
// A negative limit, or a MaxAnswerBytes below 2 * MaxMessageSize, is ErrInvalidArgument.
func NewServerWith(authorize func(peer, owner ed25519.PublicKey, logID kololog.LogID) Access, opts *ServerOptions) (*Server, error) {
	var o ServerOptions
	if opts != nil {
		o = *opts
	}
	if o.MaxTotalStreams < 0 || o.MaxAnswerBytes < 0 || (o.MaxAnswerBytes != 0 && o.MaxAnswerBytes < 2*MaxMessageSize) {
		return nil, ErrInvalidArgument
	}
	if o.MaxTotalStreams == 0 {
		o.MaxTotalStreams = DefaultMaxTotalStreams
	}
	if o.MaxAnswerBytes == 0 {
		o.MaxAnswerBytes = DefaultMaxAnswerBytes
	}
	return &Server{authorize: authorize, logs: make(map[logName]Source), limits: o}, nil
}

// take reserves n of the counter c unless that passes limit.
func (s *Server) take(c *atomic.Int64, n, limit int64) bool {
	for {
		cur := c.Load()
		if cur+n > limit {
			s.refused.Add(1)
			return false
		}
		if c.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// answer builds an answer under MaxAnswerBytes. It reserves room for a full answer before reading the log, so a
// refusal reads nothing, then sets the reservation to the answer's real size. The caller frees held once the answer
// is written and wiped.
func (s *Server) answer(build func() (message, uint64)) (m message, code uint64, held int64) {
	held = 2 * answerBudget
	if !s.take(&s.held, held, s.limits.MaxAnswerBytes) {
		return message{}, codeBusy, 0
	}
	m, code = build()
	if code != 0 {
		s.held.Add(-held)
		return m, code, 0
	}
	if need := 2 * int64(bound(m)); need > held {
		if !s.take(&s.held, need-held, s.limits.MaxAnswerBytes) {
			wipe(m)
			s.held.Add(-held)
			return message{}, codeBusy, 0
		}
		held = need
	}
	return m, 0, held
}

// Offer makes src available under its owner's key and log ID, replacing an earlier source with both the same.
// src's header must be signed by its owner and name src's log ID; past that, Offer trusts src to serve that log.
func (s *Server) Offer(src Source) error {
	if src == nil {
		return ErrInvalidArgument
	}
	h := src.Header()
	if h.LogID != src.ID() {
		return fmt.Errorf("%w: %w: the header names another log than the source", ErrInvalidArgument, kololog.ErrBadLogHeader)
	}
	if err := kololog.VerifyLogHeader(h.LogKey, h); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	n, _ := nameOf(h.LogKey, h.LogID)
	s.mu.Lock()
	s.logs[n] = src
	s.mu.Unlock()
	return nil
}

// Withdraw stops offering the log logID of owner; requests for it then get the answer of a missing log.
func (s *Server) Withdraw(owner ed25519.PublicKey, logID kololog.LogID) {
	n, ok := nameOf(owner, logID)
	if !ok {
		return
	}
	s.mu.Lock()
	delete(s.logs, n)
	s.mu.Unlock()
}

// Serve answers the streams the peer opens on conn, for Pull, PullCiphertext, FetchHeader, FetchHead, Fetch,
// FetchWithKeys and FetchKeys, until ctx is done or conn ends, then waits for them.
// It must be the only caller of conn.AcceptStream.
func (s *Server) Serve(ctx context.Context, conn Conn) error {
	if noConn(conn) {
		return ErrInvalidArgument
	}
	peer := conn.RemotePublicKey()
	if len(peer) != ed25519.PublicKeySize {
		return ErrInvalidArgument
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	slots := make(chan struct{}, MaxStreams)
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ioErr(err)
		}
		select {
		case slots <- struct{}{}:
			if !s.take(&s.taken, 1, int64(s.limits.MaxTotalStreams)) {
				<-slots
				s.busy(st)
				continue
			}
			wg.Go(func() {
				defer func() {
					s.taken.Add(-1)
					<-slots
				}()
				s.serveStream(ctx, peer, st)
			})
		default:
			s.busy(st)
		}
	}
}

// busy refuses st. The request is already sent and the answer fits in any stream window, so this does not block.
func (s *Server) busy(st *kolotransport.Stream) {
	_ = s.write(st, message{typ: tError, code: codeBusy})
	end(st)
}

// end closes the send side and stops reading.
func end(st *kolotransport.Stream) {
	_ = st.Close()
	_ = st.CancelRead(0)
}

func (s *Server) access(peer, owner ed25519.PublicKey, logID kololog.LogID) (a Access) {
	if s.authorize == nil {
		return NoAccess
	}
	defer func() {
		if recover() != nil {
			a = NoAccess
		}
	}()
	return s.authorize(peer, owner, logID)
}

// lookup asks authorize before looking at the offered logs, so missing, unoffered and unauthorized logs take one path.
func (s *Server) lookup(peer, owner ed25519.PublicKey, logID kololog.LogID) (Source, Access) {
	a := s.access(peer, owner, logID)
	n, _ := nameOf(owner, logID)
	s.mu.RLock()
	src := s.logs[n]
	s.mu.RUnlock()
	if src == nil || (a != Ciphertext && a != Keys) {
		return nil, NoAccess
	}
	return src, a
}

func (s *Server) serveStream(ctx context.Context, peer ed25519.PublicKey, st *kolotransport.Stream) {
	s.active.Add(1)
	defer s.active.Add(-1)
	stop := context.AfterFunc(ctx, func() {
		_ = st.CancelRead(0)
		_ = st.CancelWrite(0)
	})
	defer stop()
	defer end(st)
	fail := func(code uint64) {
		if code != 0 {
			_ = s.write(st, message{typ: tError, code: code})
		}
	}

	m, err := readMsg(st, true)
	if err != nil {
		fail(readCode(err))
		return
	}
	if m.typ != tHeadReq {
		fail(codeProtocol)
		return
	}
	owner, logID := ed25519.PublicKey(m.owner[:]), m.logID
	src, _ := s.lookup(peer, owner, logID)
	if src == nil {
		fail(codeNotFound)
		return
	}
	h, err := src.Head()
	if errors.Is(err, kololog.ErrNoHead) {
		fail(codeNotFound)
		return
	}
	if err != nil {
		fail(codeBusy)
		return
	}
	if s.write(st, message{typ: tHead, head: h.Encode(), header: src.Header().Encode()}) != nil {
		return
	}
	size := h.Size
	var f feed
	for {
		m, err := readMsg(st, true)
		if err != nil {
			fail(readCode(err))
			return
		}
		// Asked again, so a withdrawn log or a revoked peer stops at its next request.
		src, a := s.lookup(peer, owner, logID)
		if src == nil {
			fail(codeNotFound)
			return
		}
		if m.typ == tStreamReq || m.typ == tCreditReq {
			code := f.apply(m, size)
			if code == 0 {
				var alive bool
				if code, alive = s.pump(ctx, st, peer, owner, logID, &f); !alive {
					return
				}
			}
			if code != 0 {
				fail(code)
				return
			}
			continue
		}
		var resp message
		var held int64
		code := uint64(0)
		switch {
		case m.a > m.b || m.b > size || (m.typ != tProofReq && m.b == size):
			code = codeProtocol
		case m.typ == tFetchReq && (m.b >= m.size || m.size > size):
			code = codeProtocol
		case m.typ == tProofReq:
			resp, code = proof(src, m.a, m.b)
		case m.typ == tEntriesReq:
			resp, code, held = s.answer(func() (message, uint64) { return entries(src, a == Keys && m.keys, m.a, m.b, 0) })
		case m.typ == tFetchReq:
			resp, code, held = s.answer(func() (message, uint64) { return entries(src, a == Keys, m.a, m.b, m.size) })
		case m.typ == tStateReq:
			resp, code, held = s.answer(func() (message, uint64) { return state(src, a == Keys && m.keys, m.a, m.b) })
		default:
			code = codeProtocol
		}
		if code != 0 {
			fail(code)
			return
		}
		err = s.write(st, resp)
		wipe(resp)
		s.held.Add(-held)
		if err != nil {
			return
		}
	}
}

// maxCredit is the most credit one stream holds at once; a request for more is refused.
const maxCredit = 64 << 20

// feed is the stream of ENTRIES answers that STREAM_REQ opens on a stream: from next up to size, while the credit the
// peer granted lasts. Each answer costs its message length, which may leave the credit below 0.
type feed struct {
	open   bool
	next   uint64
	size   uint64
	keys   bool
	credit int64
}

// apply takes a STREAM_REQ, which starts a feed, or a CREDIT_REQ, which adds credit to it, for a head of head entries,
// and returns the error code of a request that is not valid.
func (f *feed) apply(m message, head uint64) uint64 {
	if m.credit == 0 || m.credit > maxCredit {
		return codeProtocol
	}
	switch m.typ {
	case tStreamReq:
		if m.size == 0 || m.size > head || m.a >= m.size {
			return codeProtocol
		}
		*f = feed{open: true, next: m.a, size: m.size, keys: m.keys, credit: int64(m.credit)}
	case tCreditReq:
		if !f.open {
			return codeProtocol
		}
		f.credit = min(f.credit+int64(m.credit), maxCredit)
	default:
		return codeProtocol
	}
	return 0
}

// pump sends the answers the credit of f pays for: each ENTRIES answer from f.next on, then the proof of its end unless
// it reaches f.size. The log is asked again before each answer, so a revoked peer or a withdrawn log stops it at once.
// It returns the error code to send, if any, and false if the stream cannot be written to or the context is done.
func (s *Server) pump(ctx context.Context, st *kolotransport.Stream, peer, owner ed25519.PublicKey, logID kololog.LogID, f *feed) (uint64, bool) {
	for f.credit > 0 && f.next < f.size {
		if ctx.Err() != nil {
			return 0, false
		}
		src, a := s.lookup(peer, owner, logID)
		if src == nil {
			return codeNotFound, true
		}
		resp, code, held := s.answer(func() (message, uint64) { return entries(src, a == Keys && f.keys, f.next, f.size-1, 0) })
		if code != 0 {
			return code, true
		}
		n, err := s.writeN(st, resp)
		k := uint64(len(resp.entries))
		wipe(resp)
		s.held.Add(-held)
		if err != nil {
			return 0, false
		}
		f.credit -= int64(n - 4)
		f.next += k
		if f.next < f.size {
			pr, code := proof(src, f.next, f.size)
			if code != 0 {
				return code, true
			}
			if s.write(st, pr) != nil {
				return 0, false
			}
		}
	}
	return 0, true
}

// wipe zeroes the entry keys a message holds.
func wipe(m message) {
	for _, e := range m.entries {
		clear(e.Key)
	}
	for _, it := range m.items {
		clear(it.key)
	}
}

// readCode is the answer to a request that could not be read; 0 sends none.
func readCode(err error) uint64 {
	switch {
	case errors.Is(err, ErrTooLarge):
		return codeTooLarge
	case errors.Is(err, errMalformed):
		return codeProtocol
	}
	return 0
}

func proof(src Source, first, second uint64) (message, uint64) {
	p, err := src.ConsistencyProof(first, second)
	if err != nil {
		return message{}, codeBusy
	}
	return message{typ: tProof, proof: p.Encode()}, 0
}

// answerBudget is the size an answer is filled to once it holds an entry: about 1 MiB, so a slow path delivers a whole
// answer long before a 4 MiB one would arrive. An entry larger than this still goes alone, up to MaxMessageSize.
const answerBudget = 1 << 20

// entries answers ENTRIES_REQ from start up to end, as many as fit in an answer. If size is not 0, it answers
// FETCH_REQ: each entry comes with its inclusion proof in the tree of size entries. The record's size and the
// proof are checked first, so an entry that cannot fit is never read.
func entries(src Source, keys bool, start, end, size uint64) (message, uint64) {
	m := message{typ: tEntries}
	if size != 0 {
		m.typ = tFetch
	}
	n := overhead
	for i := start; i <= end; i++ {
		r, err := src.Record(i)
		if err != nil {
			wipe(m)
			return message{}, codeBusy
		}
		var p []byte
		if size != 0 {
			ip, err := src.InclusionProof(i, size)
			if err != nil {
				wipe(m)
				return message{}, codeBusy
			}
			p = ip.Encode()
		}
		limit := MaxMessageSize
		if len(m.entries) > 0 {
			limit = answerBudget
		}
		if room := limit - n - len(r.Encode()) - len(p); room < 0 || r.Size > uint64(room) {
			if len(m.entries) == 0 {
				return message{}, codeTooLarge
			}
			break
		}
		e, err := src.Entry(i)
		if err != nil {
			wipe(m)
			return message{}, codeBusy
		}
		if !keys {
			clear(e.Key)
			e.Key = nil
		}
		if n += entrySize(e) + blen(p); n > limit {
			clear(e.Key)
			if len(m.entries) == 0 {
				return message{}, codeTooLarge
			}
			break
		}
		m.entries = append(m.entries, e)
		if size != 0 {
			m.proofs = append(m.proofs, p)
		}
	}
	return m, 0
}

// state lists the delete markers, and the keys if keys is set, of the entries from start up to end, as many
// as fit in one message and at most maxScan entries. It reads only markers and keys, never a ciphertext.
func state(src Source, keys bool, start, end uint64) (message, uint64) {
	m := message{typ: tState, a: end + 1}
	n := overhead
	for i := start; i <= end; i++ {
		if i-start == maxScan {
			m.a = i
			break
		}
		info, err := src.EntryInfo(i)
		if err != nil {
			wipe(m)
			return message{}, codeBusy
		}
		it := item{index: i}
		switch {
		case info.Deleted:
			e, err := src.Entry(i)
			if err != nil {
				wipe(m)
				return message{}, codeBusy
			}
			clear(e.Key)
			it.marker = e.Marker
		case keys && info.Keyed:
			k, err := src.Key(i)
			if errors.Is(err, kololog.ErrDeleted) {
				continue // deleted since EntryInfo: the next pull gets the marker
			}
			if err != nil {
				wipe(m)
				return message{}, codeBusy
			}
			it.key = k
		default:
			continue
		}
		if n += overhead + blen(it.marker) + blen(it.key); n > MaxMessageSize {
			clear(it.key)
			m.a = i
			break
		}
		m.items = append(m.items, it)
	}
	return m, 0
}
