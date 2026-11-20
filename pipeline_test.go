package kolosync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

type slowBackend struct {
	kolostore.Backend
	delay   time.Duration
	commits atomic.Int64
	stored  atomic.Uint64 // the entries committed: the highest index of a large value, plus one
	hold    chan struct{} // if set, the first commit after it waits until it is closed
	once    sync.Once
}

func (b *slowBackend) NewBatch() kolostore.Batch {
	return &slowBatch{Batch: b.Backend.NewBatch(), b: b}
}

type slowBatch struct {
	kolostore.Batch
	b    *slowBackend
	next uint64
}

// Put notes the index in the key of a value of an entry, which is larger than anything else a commit stores.
func (s *slowBatch) Put(key, value []byte) {
	if len(value) >= 10<<10 && len(key) >= 8 {
		s.next = max(s.next, binary.BigEndian.Uint64(key[len(key)-8:])+1)
	}
	s.Batch.Put(key, value)
}

func (s *slowBatch) Commit() error {
	if h := s.b.hold; h != nil {
		s.b.once.Do(func() { <-h })
	}
	time.Sleep(s.b.delay)
	s.b.commits.Add(1)
	err := s.Batch.Commit()
	if err == nil && s.next > s.b.stored.Load() {
		s.b.stored.Store(s.next)
	}
	return err
}

// holdFirstCommit makes the first commit of sb wait until the script tr has read n requests for entries, so that the answers
// queue up behind it, and a moment more for them to arrive, whatever the speed of the machine.
func holdFirstCommit(t *testing.T, sb *slowBackend, tr *trace, n int) {
	t.Helper()
	hold := make(chan struct{})
	sb.hold = hold
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(hold)
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && len(tr.entries()) < n; {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(500 * time.Millisecond) // for the answers to arrive
	}()
	t.Cleanup(func() { <-done })
}

var slowStores sync.Map

var slowReps sync.Map

func slowPeer(t *testing.T, delay time.Duration) (*peer, *slowBackend) {
	t.Helper()
	p := newPeer(t)
	sb := &slowBackend{Backend: kolostore.NewMemory(), delay: delay}
	p.st = kolostore.New(sb)
	t.Cleanup(func() { p.st.Close() })
	slowStores.Store(p.st, sb)
	return p, sb
}

// mixedSizes are n entry sizes that put from one to about ten entries in an answer.
func mixedSizes(n int) []int {
	pattern := []int{50 << 10, 300 << 10, 700 << 10, 120 << 10, 20 << 10, 450 << 10, 90 << 10}
	out := make([]int, n)
	for i := range out {
		out[i] = pattern[i%len(pattern)] + i
	}
	return out
}

// sizedLog is a log of p's with one random entry of each size, not offered.
func sizedLog(t *testing.T, p *peer, sizes []int) *kolostore.Log {
	t.Helper()
	l, err := p.st.Create(p.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	for _, n := range sizes {
		buf := make([]byte, n)
		rand.Read(buf)
		if _, err := l.Append(buf); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func openReplica(t *testing.T, p *peer, l *kolostore.Log) *kolostore.Replica {
	t.Helper()
	r, err := p.st.OpenReplica(l.Header().LogKey, l.ID(), l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if sb, ok := slowStores.Load(p.st); ok {
		slowReps.Store(r, sb)
	}
	return r
}

type trace struct {
	mu   sync.Mutex
	reqs []message
	lens []uint64 // the replica's length when the request was read
	ends []uint64 // after an ENTRIES request, the index its answer ends at
}

func (tr *trace) entries() (out []message) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, m := range tr.reqs {
		if m.typ == tEntriesReq {
			out = append(out, m)
		}
	}
	return out
}

// maxOutstanding is the most ENTRIES requests the server had read whose answers the replica did not hold yet.
func (tr *trace) maxOutstanding() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	most, asked := 0, 0
	var ends []uint64
	for i, m := range tr.reqs {
		if m.typ != tEntriesReq {
			continue
		}
		asked++
		held := 0
		for _, e := range ends {
			if e <= tr.lens[i] {
				held++
			}
		}
		most = max(most, asked-held)
		ends = append(ends, endOf(tr, i))
	}
	return most
}

// endOf is the end of the answer to the ENTRIES request at reqs[i].
func endOf(tr *trace, i int) uint64 {
	n := 0
	for _, m := range tr.reqs[:i] {
		if m.typ == tEntriesReq {
			n++
		}
	}
	return tr.ends[n]
}

// scriptFn may answer request n, read after the head request, itself, by returning true; real is the true answer.
type scriptFn func(st *kolotransport.Stream, n int, req message, real []byte) bool

// serveScript answers the next stream of conn like a Server that offers src, one request at a time, and records the requests;
// rep, if not nil, is the replica of the pulling peer, whose length is recorded with each.
func serveScript(t *testing.T, conn *kolosecure.Conn, src Source, rep *kolostore.Replica, fn scriptFn) *trace {
	t.Helper()
	tr := new(trace)
	// Len waits while an Update commits, which would stall the server, so a slow store reports what it has committed.
	lenOf := func() uint64 {
		if sb, ok := slowReps.Load(rep); ok {
			return sb.(*slowBackend).stored.Load()
		}
		if rep == nil {
			return 0
		}
		return rep.Len()
	}
	rawServe(t, conn, func(st *kolotransport.Stream) {
		if _, err := readMsg(st, true); err != nil {
			return
		}
		h, _ := src.Head()
		if _, err := writeMsg(st, message{typ: tHead, head: h.Encode(), header: src.Header().Encode()}); err != nil {
			return
		}
		for n := 0; ; n++ {
			req, err := readMsg(st, true)
			if err != nil {
				return
			}
			length := lenOf()
			var resp message
			code := uint64(0)
			switch req.typ {
			case tProofReq:
				resp, code = proof(src, req.a, req.b)
			case tEntriesReq:
				resp, code = entries(src, req.keys, req.a, req.b, 0)
			case tStateReq:
				resp, code = state(src, req.keys, req.a, req.b)
			default:
				code = codeProtocol
			}
			if code != 0 {
				resp = message{typ: tError, code: code}
			}
			tr.mu.Lock()
			tr.reqs = append(tr.reqs, req)
			tr.lens = append(tr.lens, length)
			if req.typ == tEntriesReq {
				tr.ends = append(tr.ends, req.a+uint64(len(resp.entries)))
			}
			tr.mu.Unlock()
			real := wire(resp)
			st.SetWriteDeadline(time.Time{}) // the head's deadline would cut a slow answer
			if fn != nil && fn(st, n, req, real) {
				continue
			}
			if _, err := st.Write(real); err != nil {
				return
			}
		}
	})
	return tr
}

// legacyPull is Pull as it was before the read-ahead, for a replica that holds nothing: one request, one proof, one store each.
func legacyPull(ctx context.Context, conn Conn, rep *kolostore.Replica) error {
	c, h, _, err := open(ctx, conn, rep.Header().LogKey, rep.ID())
	if err != nil {
		return err
	}
	defer c.close()
	c.keys = true
	theirs, err := kololog.VerifyHead(rep.Header().LogKey, rep.ID(), h)
	if err != nil {
		return err
	}
	m := theirs.Size()
	for start := rep.Len(); start < m; start = rep.Len() {
		resp, err := c.call(message{typ: tEntriesReq, a: start, b: m - 1, keys: true}, tEntries)
		if err != nil {
			return err
		}
		k := uint64(len(resp.entries))
		p := kololog.ConsistencyProof{OldSize: m, NewSize: m}
		if start+k < m {
			if p, err = c.proof(start+k, m); err != nil {
				return err
			}
		}
		if err := rep.Update(h, p, resp.entries); err != nil {
			return err
		}
	}
	return c.state(rep, m)
}

func sameRequests(t *testing.T, got, want []message) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d requests, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].typ != want[i].typ || got[i].a != want[i].a || got[i].b != want[i].b || got[i].keys != want[i].keys {
			t.Fatalf("request %d is %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestInFlightPullsTheSameLog(t *testing.T) {
	for depth := 0; depth <= MaxInFlight; depth++ {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			checkGoroutines(t)
			a := newPeer(t)
			b, _ := slowPeer(t, 2*time.Millisecond)
			l := sizedLog(t, a, mixedSizes(30))
			a.srv.Offer(l)
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			res, err := PullWith(testCtx(t), ba, r, &PullOptions{InFlight: depth})
			if err != nil {
				t.Fatal(err)
			}
			if res.KeysFrom != l.Len() {
				t.Fatalf("KeysFrom %d, want %d", res.KeysFrom, l.Len())
			}
			sameEntries(t, r, l)
			// A pull that is up to date asks for nothing more.
			if err := Pull(testCtx(t), ba, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInFlightOptionRange(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	for _, n := range []int{-1, MaxInFlight + 1} {
		if _, err := PullWith(testCtx(t), ba, r, &PullOptions{InFlight: n}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("InFlight %d: %v, want ErrInvalidArgument", n, err)
		}
	}
	if r.Len() != 0 {
		t.Fatalf("a refused option stored %d entries", r.Len())
	}
}

// With one answer in flight the pull is the one before the read-ahead: the same requests in the same order, each ENTRIES
// request sent only after the answer before it is stored, and the same replica.
func TestInFlightOneIsTheSerialPull(t *testing.T) {
	checkGoroutines(t)
	sizes := mixedSizes(24)
	l := sizedLog(t, newPeer(t), sizes)
	run := func(t *testing.T, pull func(context.Context, Conn, *kolostore.Replica) error) (*trace, *kolostore.Replica) {
		b, c := newPeer(t), newPeer(t)
		c.srv = nil
		r := openReplica(t, b, l)
		bc, cb := connect(t, b, c, nil)
		tr := serveScript(t, cb, l, r, nil)
		if err := pull(testCtx(t), bc, r); err != nil {
			t.Fatal(err)
		}
		return tr, r
	}
	old, rOld := run(t, legacyPull)
	now, rNow := run(t, func(ctx context.Context, c Conn, r *kolostore.Replica) error {
		_, err := PullWith(ctx, c, r, &PullOptions{InFlight: 1})
		return err
	})
	sameEntries(t, rNow, l)
	sameEntries(t, rOld, l)
	sameRequests(t, now.reqs, old.reqs)
	var proofs int
	for i, m := range now.reqs {
		if m.typ == tEntriesReq && now.lens[i] != m.a {
			t.Fatalf("request %+v read with %d entries stored: asked before the answer before it was stored", m, now.lens[i])
		}
		if m.typ == tProofReq {
			proofs++
		}
	}
	if proofs < 3 {
		t.Fatalf("%d proofs: the log fits few answers", proofs)
	}
	if n := now.maxOutstanding(); n != 1 {
		t.Fatalf("%d requests outstanding, want 1", n)
	}
}

// The next answers are asked for and travel while one is stored, never more than InFlight at a time, and the commits
// are fewer than the answers once some wait.
func TestInFlightReadsAheadAndStaysBounded(t *testing.T) {
	for _, depth := range []int{2, 3, 6, MaxInFlight} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			checkGoroutines(t)
			a, c := newPeer(t), newPeer(t)
			b, sb := slowPeer(t, 10*time.Millisecond)
			c.srv = nil
			l := sizedLog(t, a, mixedSizes(40))
			r := openReplica(t, b, l)
			bc, cb := connect(t, b, c, nil)
			tr := serveScript(t, cb, l, r, nil)
			ahead := min(depth, 6)
			holdFirstCommit(t, sb, tr, ahead)
			before := sb.commits.Load()
			if _, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: depth}); err != nil {
				t.Fatal(err)
			}
			sameEntries(t, r, l)
			commits := int(sb.commits.Load() - before)
			answers := len(tr.entries())
			if most := tr.maxOutstanding(); most < ahead || most > depth {
				t.Fatalf("%d requests outstanding at most, want %d to %d", most, ahead, depth)
			}
			if depth >= 3 && commits >= answers {
				t.Fatalf("%d commits for %d answers: nothing was batched", commits, answers)
			}
		})
	}
}

// Whatever InFlight is, the answers a pull holds stay within readAhead: with 2 MiB answers, two are held and a third is asked for.
func TestInFlightMemoryIsBounded(t *testing.T) {
	checkGoroutines(t)
	a, c := newPeer(t), newPeer(t)
	b, sb := slowPeer(t, 10*time.Millisecond)
	c.srv = nil
	sizes := make([]int, 10)
	for i := range sizes {
		sizes[i] = 2<<20 + i
	}
	l := sizedLog(t, a, sizes)
	r := openReplica(t, b, l)
	bc, cb := connect(t, b, c, nil)
	tr := serveScript(t, cb, l, r, nil)
	holdFirstCommit(t, sb, tr, 3)
	if _, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: MaxInFlight}); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
	if most := tr.maxOutstanding(); most != 3 {
		t.Fatalf("%d requests outstanding with 2 MiB answers, want 3 (two held, a third coming)", most)
	}
}

func TestGate(t *testing.T) {
	g := newGate(10)
	stop := make(chan struct{})
	if !g.acquire(4, stop) || !g.acquire(6, stop) {
		t.Fatal("acquire within the limit waited")
	}
	got := make(chan bool)
	go func() { got <- g.acquire(1, stop) }()
	select {
	case <-got:
		t.Fatal("acquired past the limit")
	case <-time.After(50 * time.Millisecond):
	}
	g.release(4)
	if !<-got {
		t.Fatal("acquire failed after a release")
	}
	g.release(6)
	g.release(1)
	// One answer is always admitted, however large.
	if !g.acquire(100, stop) {
		t.Fatal("a lone large answer was refused")
	}
	go func() { got <- g.acquire(1, stop) }()
	close(stop)
	if <-got {
		t.Fatal("acquire succeeded after stop")
	}
}

func TestEntriesCount(t *testing.T) {
	m := message{typ: tEntries, entries: []kololog.Entry{{Record: make([]byte, minSigned)}, {Record: make([]byte, minSigned)}}}
	b := encode(m)
	if n, ok := entriesCount(b[:min(len(b), peekSize)]); !ok || n != 2 {
		t.Fatalf("entriesCount = %d, %v, want 2", n, ok)
	}
	for name, b := range map[string][]byte{
		"empty":      nil,
		"version":    {2, tEntries, 1},
		"type":       {version, tProof, 1},
		"no count":   {version, tEntries},
		"cut varint": {version, tEntries, 0x80},
	} {
		if _, ok := entriesCount(b); ok {
			t.Errorf("%s: counted", name)
		}
	}
}

// cutAfter makes a script that ends the stream when it reads the ENTRIES request number n (from 0).
func cutAfter(n int) scriptFn {
	seen := 0
	return func(st *kolotransport.Stream, _ int, req message, _ []byte) bool {
		if req.typ != tEntriesReq {
			return false
		}
		seen++
		if seen > n {
			st.Close() // the answers before it arrive whole, then the stream ends
			st.CancelRead(0)
			return true
		}
		return false
	}
}

// A pull cut off in the middle keeps the answers that arrived whole, and a later pull from the same replica ends with the same log.
func TestInFlightCutThenResume(t *testing.T) {
	for _, depth := range []int{1, 3, MaxInFlight} {
		for cut := 1; cut <= 4; cut++ {
			t.Run(fmt.Sprintf("depth %d cut %d", depth, cut), func(t *testing.T) {
				checkGoroutines(t)
				a, b, c := newPeer(t), newPeer(t), newPeer(t)
				c.srv = nil
				l := sizedLog(t, a, mixedSizes(30))
				a.srv.Offer(l)
				r := openReplica(t, b, l)
				bc, cb := connect(t, b, c, nil)
				tr := serveScript(t, cb, l, r, cutAfter(cut))
				_, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: depth})
				if err == nil {
					t.Fatal("Pull succeeded on a cut stream")
				}
				tr.mu.Lock()
				ends := append([]uint64(nil), tr.ends...)
				tr.mu.Unlock()
				if len(ends) < cut {
					t.Fatalf("the server answered %d, want %d", len(ends), cut)
				}
				// Every answer that arrived whole is stored, and nothing else.
				if r.Len() != ends[cut-1] {
					t.Fatalf("Len %d after the cut, want %d, the end of answer %d", r.Len(), ends[cut-1], cut)
				}
				if _, err := r.Head(); !errors.Is(err, kololog.ErrNoHead) {
					t.Fatalf("Head %v: a partial pull has no head", err)
				}
				ba, _ := connect(t, b, a, nil)
				if err := Pull(testCtx(t), ba, r); err != nil {
					t.Fatal(err)
				}
				sameEntries(t, r, l)
			})
		}
	}
}

// outcome is what a pull of a hostile source leaves behind.
type outcome struct {
	err  error
	n    uint64
	head string
}

func outcomeOf(t *testing.T, err error, r *kolostore.Replica) outcome {
	t.Helper()
	return outcome{err, r.Len(), snapshot(t, r)}
}

// Whatever the peer serves while answers are in flight, the replica holds what a pull with one answer in flight holds,
// with the same error, and a pull from an honest peer then ends with the right log.
func TestInFlightHostileSourceLeavesTheSameReplica(t *testing.T) {
	sizes := mixedSizes(40)
	for _, tc := range []struct {
		name string
		src  func(l *kolostore.Log) Source
		want error
	}{
		{"bad ciphertext", func(l *kolostore.Log) Source {
			return tamper{Source: l, entry: func(i uint64, e *kololog.Entry) {
				if i == 6 {
					e.Ciphertext[0] ^= 1
				}
			}}
		}, ErrInvalid},
		{"bad record", func(l *kolostore.Log) Source {
			return tamper{Source: l, entry: func(i uint64, e *kololog.Entry) {
				if i == 7 {
					e.Record[len(e.Record)-1] ^= 1
				}
			}}
		}, ErrInvalid},
		{"bad proof", func(l *kolostore.Log) Source {
			return tamper{Source: l, proof: func(p *kololog.ConsistencyProof) {
				if len(p.Path) > 0 && p.OldSize >= 9 { // from the end of the third answer on
					p.Path[0][0] ^= 1
				}
			}}
		}, ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			var want outcome
			for _, depth := range []int{1, 3, MaxInFlight} {
				// The first commit waits for the next answers, so that they are stored together.
				a, c := newPeer(t), newPeer(t)
				b, sb := slowPeer(t, 10*time.Millisecond)
				c.srv = nil
				l := sizedLog(t, a, sizes)
				r := openReplica(t, b, l)
				bc, cb := connect(t, b, c, nil)
				tr := serveScript(t, cb, tc.src(l), r, nil)
				holdFirstCommit(t, sb, tr, min(depth, 3))
				_, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: depth})
				got := outcomeOf(t, err, r)
				if !errors.Is(err, tc.want) || got.n == 0 || got.n >= l.Len() {
					t.Fatalf("depth %d: Pull = %v with %d of %d entries, want %v and a stored prefix", depth, err, got.n, l.Len(), tc.want)
				}
				if depth == 1 {
					want = got
				} else if got.n != want.n || got.head != want.head {
					t.Fatalf("depth %d stored %d entries, depth 1 stored %d", depth, got.n, want.n)
				}
				a.srv.Offer(l)
				ba, _ := connect(t, b, a, nil)
				if err := Pull(testCtx(t), ba, r); err != nil {
					t.Fatalf("depth %d: resume: %v", depth, err)
				}
				sameEntries(t, r, l)
			}
		})
	}
}

// answer k of a scripted server is replaced by raw.
func replaceEntries(k int, raw func(real []byte) []byte) scriptFn {
	seen := 0
	return func(st *kolotransport.Stream, _ int, req message, real []byte) bool {
		if req.typ != tEntriesReq {
			return false
		}
		seen++
		if seen != k+1 {
			return false
		}
		st.Write(raw(real))
		return true
	}
}

func TestInFlightHostileAnswers(t *testing.T) {
	const k = 2 // the third answer
	// before20 is the end of the last answer that ends at or before 20, the one before the answer whose proof the peer spoils.
	before20 := func(ends []uint64) (n uint64) {
		for _, e := range ends {
			if e <= 20 {
				n = e
			}
		}
		return n
	}
	for _, tc := range []struct {
		name string
		fn   scriptFn
		want error
		keep func(ends []uint64) uint64 // the entries the pull stores before it fails
	}{
		{"oversized frame", replaceEntries(k, func([]byte) []byte { return frame(MaxMessageSize+1, nil) }), ErrTooLarge, nil},
		{"garbage", replaceEntries(k, func([]byte) []byte { return frame(20, bytes.Repeat([]byte{0xff}, 20)) }), ErrProtocol, nil},
		{"a proof for entries", replaceEntries(k, func([]byte) []byte { return wire(message{typ: tProof, proof: []byte{1}}) }), ErrProtocol, nil},
		{"refusal", replaceEntries(k, func([]byte) []byte { return wire(message{typ: tError, code: codeBusy}) }), ErrBusy, nil},
		{"count the body does not hold", replaceEntries(k, func(real []byte) []byte {
			b := append([]byte(nil), real[4:]...)
			b[2] += 2 // the count follows the version and the type: asks for more entries than follow
			return frame(uint32(len(b)), b)
		}), ErrProtocol, nil},
		{"no entries", replaceEntries(k, func([]byte) []byte { return wire(message{typ: tEntries}) }), ErrProtocol, nil},
		{"refused proof", func(st *kolotransport.Stream, _ int, req message, _ []byte) bool {
			if req.typ == tProofReq && req.a > 20 {
				st.Write(wire(message{typ: tError, code: codeBusy}))
				return true
			}
			return false
		}, ErrBusy, before20},
		{"entries for a proof", func(st *kolotransport.Stream, _ int, req message, _ []byte) bool {
			if req.typ == tProofReq && req.a > 20 {
				st.Write(wire(message{typ: tEntries, entries: []kololog.Entry{{Record: make([]byte, minSigned)}}}))
				return true
			}
			return false
		}, ErrProtocol, before20},
		{"truncated body", replaceEntries(k, func(real []byte) []byte { return real[:len(real)/2] }), ErrProtocol, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			c.srv = nil
			l := sizedLog(t, a, mixedSizes(40))
			a.srv.Offer(l)
			r := openReplica(t, b, l)
			bc, cb := connect(t, b, c, nil)
			fn := tc.fn
			if tc.name == "truncated body" {
				orig := fn
				fn = func(st *kolotransport.Stream, n int, req message, real []byte) bool {
					handled := orig(st, n, req, real)
					if handled {
						st.Close()
					}
					return handled
				}
			}
			tr := serveScript(t, cb, l, r, fn)
			_, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 4})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Pull = %v, want %v", err, tc.want)
			}
			tr.mu.Lock()
			ends := append([]uint64(nil), tr.ends...)
			tr.mu.Unlock()
			// The answers before the bad one are stored, and not the bad one.
			keep := ends[k-1]
			if tc.keep != nil {
				keep = tc.keep(ends)
			}
			if r.Len() != keep {
				t.Fatalf("Len %d, want %d: the answers before the bad one", r.Len(), keep)
			}
			if _, err := r.Head(); !errors.Is(err, kololog.ErrNoHead) {
				t.Fatalf("Head %v: a failed pull has no head", err)
			}
			ba, _ := connect(t, b, a, nil)
			if err := Pull(testCtx(t), ba, r); err != nil {
				t.Fatal(err)
			}
			sameEntries(t, r, l)
		})
	}
}

// A peer that sends answers of the largest size, one after another, never makes the pull hold more than readAhead.
func TestInFlightHostileLargeAnswers(t *testing.T) {
	checkGoroutines(t)
	a, c := newPeer(t), newPeer(t)
	b, sb := slowPeer(t, 10*time.Millisecond)
	c.srv = nil
	sizes := make([]int, 8)
	for i := range sizes {
		sizes[i] = 3<<20 + i
	}
	l := sizedLog(t, a, sizes)
	r := openReplica(t, b, l)
	bc, cb := connect(t, b, c, nil)
	tr := serveScript(t, cb, l, r, nil)
	holdFirstCommit(t, sb, tr, 2)
	if _, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: MaxInFlight}); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
	if most := tr.maxOutstanding(); most != 2 {
		t.Fatalf("%d requests outstanding with 3 MiB answers, want 2 (one held, one coming)", most)
	}
}

// Cancelling, or a deadline, in the middle of a read-ahead returns the context's error at once, leaks nothing and leaves
// a replica that a later pull completes.
func TestInFlightCancel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		depth int
		delay time.Duration // of each commit
		limit time.Duration // of the pull's context, 0 for none
	}{
		{"cancel, depth 1", 1, 5 * time.Millisecond, 0},
		{"cancel, depth 3", 3, 5 * time.Millisecond, 0},
		{"cancel, depth 8", MaxInFlight, 5 * time.Millisecond, 0},
		{"cancel, slow commits", 4, 200 * time.Millisecond, 0},
		{"deadline", 3, 5 * time.Millisecond, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, c := newPeer(t), newPeer(t)
			b, _ := slowPeer(t, tc.delay)
			c.srv = nil
			l := sizedLog(t, a, mixedSizes(60))
			a.srv.Offer(l)
			r := openReplica(t, b, l)
			bc, cb := connect(t, b, c, nil)
			// The server is slow, so the pull is still in the middle when the context ends.
			tr := serveScript(t, cb, l, r, func(_ *kolotransport.Stream, _ int, req message, _ []byte) bool {
				if req.typ == tEntriesReq {
					time.Sleep(150 * time.Millisecond)
				}
				return false
			})
			ctx, cancel := context.WithCancel(testCtx(t))
			defer cancel()
			want := context.Canceled
			var cancelled atomic.Int64
			if tc.limit != 0 {
				ctx, cancel = context.WithTimeout(ctx, tc.limit)
				defer cancel()
				want = context.DeadlineExceeded
			} else {
				go func() {
					for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && len(tr.entries()) < 4; {
						time.Sleep(5 * time.Millisecond)
					}
					cancelled.Store(time.Now().UnixNano())
					cancel()
				}()
			}
			_, err := PullWith(ctx, bc, r, &PullOptions{InFlight: tc.depth})
			if !errors.Is(err, want) {
				t.Fatalf("Pull = %v, want %v", err, want)
			}
			if r.Len() >= l.Len() {
				t.Fatalf("Len %d of %d: the pull was not cut in the middle", r.Len(), l.Len())
			}
			if at := cancelled.Load(); at != 0 && time.Since(time.Unix(0, at)) > 3*time.Second {
				t.Fatalf("Pull returned %v after the cancel", time.Since(time.Unix(0, at)))
			}
			ba, _ := connect(t, b, a, nil)
			if err := Pull(testCtx(t), ba, r); err != nil {
				t.Fatal(err)
			}
			sameEntries(t, r, l)
		})
	}
}

// A message that is slow but within its allowance is read while the next ones are in flight, and one that stalls
// ends the pull with ErrTimeout, as without the read-ahead.
func TestInFlightKeepsTheMessageDeadlines(t *testing.T) {
	t.Run("slow within the allowance", func(t *testing.T) {
		checkGoroutines(t)
		a, b, c := newPeer(t), newPeer(t), newPeer(t)
		c.srv = nil
		l := sizedLog(t, a, []int{60 << 10, 60 << 10})
		r := openReplica(t, b, l)
		bc, cb := connect(t, b, c, nil)
		serveScript(t, cb, l, r, func(st *kolotransport.Stream, _ int, req message, real []byte) bool {
			if req.typ != tEntriesReq || req.a != 0 {
				return false
			}
			for len(real) > 0 {
				n := min(len(real), 25<<10)
				st.Write(real[:n])
				real = real[n:]
				time.Sleep(1100 * time.Millisecond) // over the timeout in all, within the allowance
			}
			return true
		})
		if _, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 4}); err != nil {
			t.Fatal(err)
		}
		sameEntries(t, r, l)
	})
	t.Run("stalled", func(t *testing.T) {
		checkGoroutines(t)
		a, b, c := newPeer(t), newPeer(t), newPeer(t)
		c.srv = nil
		l := sizedLog(t, a, []int{1200 << 10, 20 << 10, 20 << 10}) // a large answer, then a small one
		r := openReplica(t, b, l)
		bc, cb := connect(t, b, c, nil)
		tr := serveScript(t, cb, l, r, func(st *kolotransport.Stream, _ int, req message, real []byte) bool {
			if req.typ == tEntriesReq && req.a > 0 {
				st.Write(real[:len(real)/2]) // then nothing
				time.Sleep(timeout + allowance(len(real)) + time.Second)
				return true
			}
			return false
		})
		_, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 4})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("Pull = %v, want ErrTimeout", err)
		}
		tr.mu.Lock()
		first := tr.ends[0]
		tr.mu.Unlock()
		if r.Len() != first {
			t.Fatalf("Len %d, want %d, the end of the first answer", r.Len(), first)
		}
	})
}

// An old client, which asks for one answer and its proof at a time, pulls from this server; every other test pulls with the
// read-ahead from the same server, or from a script that answers one request at a time like it. The wire format is the same.
func TestInFlightInteroperates(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := sizedLog(t, a, mixedSizes(30))
	a.srv.Offer(l)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := legacyPull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

// A pull that finds a marker among entries it asked for with NoMarkers stops at it with the same replica at any depth,
// whether the marker comes first in an answer, inside one, or after others.
func TestInFlightNoMarkers(t *testing.T) {
	for _, at := range []uint64{0, 1, 4, 11, 19, 29} {
		var want outcome
		for _, depth := range []int{1, 3, MaxInFlight} {
			t.Run(fmt.Sprintf("marker %d depth %d", at, depth), func(t *testing.T) {
				checkGoroutines(t)
				a, b := newPeer(t), newPeer(t)
				l := sizedLog(t, a, mixedSizes(30))
				if err := l.Delete(at); err != nil {
					t.Fatal(err)
				}
				a.srv.Offer(l)
				ba, _ := connect(t, b, a, nil)
				r := replica(t, b, ba, a.id.PublicKey(), l.ID())
				_, err := PullWith(testCtx(t), ba, r, &PullOptions{NoMarkers: true, InFlight: depth})
				if !errors.Is(err, ErrMarked) {
					t.Fatalf("Pull = %v, want ErrMarked", err)
				}
				if r.Len() != at {
					t.Fatalf("Len %d, want %d", r.Len(), at)
				}
				got := outcomeOf(t, err, r)
				if depth == 1 {
					want = got
				} else if got.head != want.head || got.err.Error() != want.err.Error() {
					t.Fatalf("depth %d left %+v, depth 1 left %+v", depth, got, want)
				}
				if err := Pull(testCtx(t), ba, r); err != nil {
					t.Fatal(err)
				}
				if info, err := r.EntryInfo(at); err != nil || !info.Deleted || r.Len() != l.Len() {
					t.Fatalf("after the next pull: Len %d of %d, entry %d is %+v, %v", r.Len(), l.Len(), at, info, err)
				}
			})
		}
	}
}

// Several pulls of different replicas at once on one connection, each reading ahead, all end with their logs.
func TestInFlightConcurrentPulls(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	ba, _ := connect(t, b, a, nil)
	var logs []*kolostore.Log
	var reps []*kolostore.Replica
	for range 4 {
		l := sizedLog(t, a, mixedSizes(25))
		a.srv.Offer(l)
		logs = append(logs, l)
		reps = append(reps, replica(t, b, ba, a.id.PublicKey(), l.ID()))
	}
	var wg sync.WaitGroup
	errs := make([]error, len(logs))
	for i := range logs {
		wg.Go(func() { _, errs[i] = PullWith(testCtx(t), ba, reps[i], &PullOptions{InFlight: 3}) })
	}
	wg.Wait()
	for i := range logs {
		if errs[i] != nil {
			t.Fatalf("pull %d: %v", i, errs[i])
		}
		sameEntries(t, reps[i], logs[i])
	}
}

// bigForks returns two copies of one log of id that share their first shared entries and then add the entries of sizes
// each, with other contents.
func bigForks(t *testing.T, id *koloid.Identity, shared int, sizes []int) (*kololog.Replica, *kololog.Replica) {
	t.Helper()
	l, err := kololog.New(id, kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	add := func(f interface{ Append(any) (uint64, error) }, sizes []int) {
		for _, n := range sizes {
			buf := make([]byte, n)
			rand.Read(buf)
			if _, err := f.Append(buf); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(l, mixedSizes(shared))
	header := l.Header().Encode()
	h, entries := dump(t, l)
	l.Close()
	grow := func() *kololog.Replica {
		f, err := kololog.Restore(id, header, h.Encode(), stored(t, entries))
		if err != nil {
			t.Fatal(err)
		}
		add(f, sizes)
		fh, fe := dump(t, f)
		f.Close()
		r, err := kololog.RestoreReplica(id.PublicKey(), f.ID(), header, kololog.Heads{Head: &fh}, stored(t, fe))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	return grow(), grow()
}

// A peer whose history forks from the entries the replica holds is found while answers are in flight: the answers still on
// the stream are read before the peer's record is asked for, and the pull ends with ErrDiverged and the replica as it was.
func TestInFlightFindsAFork(t *testing.T) {
	for _, depth := range []int{1, 3, MaxInFlight} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			checkGoroutines(t)
			a, b, c, d := newPeer(t), newPeer(t), newPeer(t), newPeer(t)
			c.srv, d.srv = nil, nil
			ra, rb := bigForks(t, a.id, 3, mixedSizes(40))
			hdr := ra.Header()
			r, err := b.st.OpenReplica(hdr.LogKey, ra.ID(), hdr.Encode())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { r.Close() })
			// The replica holds the first answers of one branch, from a pull that was cut off.
			bc, cb := connect(t, b, c, nil)
			serveScript(t, cb, ra, r, cutAfter(2))
			if err := Pull(testCtx(t), bc, r); err == nil || r.Len() <= 3 {
				t.Fatalf("Pull = %v, Len %d: the cut pull must fail with entries past the shared ones", err, r.Len())
			}
			before := snapshot(t, r)
			bd, db := connect(t, b, d, nil)
			serveScript(t, db, rb, r, nil)
			_, err = PullWith(testCtx(t), bd, r, &PullOptions{InFlight: depth})
			if !errors.Is(err, ErrDiverged) {
				t.Fatalf("Pull = %v, want ErrDiverged", err)
			}
			if after := snapshot(t, r); after != before {
				t.Fatalf("replica changed: %s, was %s", after, before)
			}
		})
	}
}

// A peer that sends an answer and closes the stream, so that the proof and the next request written while it arrives go
// nowhere, still has the answers before it stored, and the pull returns an error the next pull recovers from.
func TestInFlightPeerClosesAfterAnAnswer(t *testing.T) {
	for _, depth := range []int{1, 3} {
		for _, k := range []int{1, 3} {
			t.Run(fmt.Sprintf("depth %d answer %d", depth, k), func(t *testing.T) {
				checkGoroutines(t)
				a, b, c := newPeer(t), newPeer(t), newPeer(t)
				c.srv = nil
				l := sizedLog(t, a, mixedSizes(30))
				a.srv.Offer(l)
				r := openReplica(t, b, l)
				bc, cb := connect(t, b, c, nil)
				seen := 0
				tr := serveScript(t, cb, l, r, func(st *kolotransport.Stream, _ int, req message, real []byte) bool {
					if req.typ != tEntriesReq {
						return false
					}
					seen++
					if seen != k {
						return false
					}
					st.Write(real)
					st.Close()
					st.CancelRead(0)
					time.Sleep(100 * time.Millisecond)
					return true
				})
				if _, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: depth}); err == nil {
					t.Fatal("Pull succeeded on a stream the peer closed")
				}
				tr.mu.Lock()
				var want uint64
				if k > 1 {
					want = tr.ends[k-2]
				}
				tr.mu.Unlock()
				if r.Len() != want {
					t.Fatalf("Len %d, want %d: the answers before the last one, which has no proof", r.Len(), want)
				}
				ba, _ := connect(t, b, a, nil)
				if err := Pull(testCtx(t), ba, r); err != nil {
					t.Fatal(err)
				}
				sameEntries(t, r, l)
			})
		}
	}
}
