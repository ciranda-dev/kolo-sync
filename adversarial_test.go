package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// tamper serves src with its head or entries changed.
type tamper struct {
	Source
	head  func(*kololog.Head)
	entry func(uint64, *kololog.Entry)
	proof func(*kololog.ConsistencyProof)
	incl  func(*kololog.InclusionProof)
}

func (s tamper) InclusionProof(index, size uint64) (kololog.InclusionProof, error) {
	p, err := s.Source.InclusionProof(index, size)
	if err == nil && s.incl != nil {
		s.incl(&p)
	}
	return p, err
}

func (s tamper) ConsistencyProof(oldSize, newSize uint64) (kololog.ConsistencyProof, error) {
	p, err := s.Source.ConsistencyProof(oldSize, newSize)
	if err == nil && s.proof != nil {
		s.proof(&p)
	}
	return p, err
}

func (s tamper) Head() (kololog.Head, error) {
	h, err := s.Source.Head()
	if err == nil && s.head != nil {
		s.head(&h)
	}
	return h, err
}

func (s tamper) Entry(i uint64) (kololog.Entry, error) {
	e, err := s.Source.Entry(i)
	if err == nil && s.entry != nil {
		s.entry(i, &e)
	}
	return e, err
}

// forks returns three copies of one log of id: its first base entries, and two that add na and nb others to them.
func forks(t *testing.T, id *koloid.Identity, base, na, nb int) (*kololog.Replica, *kololog.Replica, *kololog.Replica) {
	t.Helper()
	l, err := kololog.New(id, kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, base)
	header := l.Header().Encode()
	h, entries := dump(t, l)
	l.Close()
	grow := func(n int, tag string) *kololog.Replica {
		f, err := kololog.Restore(id, header, h.Encode(), stored(t, entries))
		if err != nil {
			t.Fatal(err)
		}
		for i := range n {
			if _, err := f.Append([]byte(fmt.Sprintf("%s %d", tag, i))); err != nil {
				t.Fatal(err)
			}
		}
		fh, fe := dump(t, f)
		f.Close()
		r, err := kololog.RestoreReplica(id.PublicKey(), f.ID(), header, kololog.Heads{Head: &fh}, stored(t, fe))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	return grow(0, ""), grow(na, "a"), grow(nb, "b")
}

func stored(t *testing.T, entries []kololog.Entry) kololog.Storage {
	t.Helper()
	s := kololog.NewMemory()
	if err := s.Commit(kololog.Change{Entries: entries}); err != nil {
		t.Fatal(err)
	}
	return s
}

func dump(t *testing.T, l *kololog.Log) (kololog.Head, []kololog.Entry) {
	t.Helper()
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	var out []kololog.Entry
	for i := range l.Len() {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return h, out
}

func TestDiverged(t *testing.T) {
	for _, tc := range []struct {
		name string
		nb   int // entries the peer's copy adds to the 3 shared ones; -1 serves the shared prefix
		want error
	}{
		{"same size", 2, ErrDiverged},
		{"peer longer", 4, ErrDiverged},
		{"peer shorter", 1, ErrDiverged},
		{"peer is a prefix", -1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			base, ra, rb := forks(t, a.id, 3, 2, max(tc.nb, 0))
			if tc.nb < 0 {
				rb = base
			}
			a.srv.Offer(ra)
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), ra.ID())
			if err := Pull(testCtx(t), ba, r); err != nil {
				t.Fatal(err)
			}
			before, peerHead := snapshot(t, r), headOf(t, rb)
			a.srv.Offer(rb)
			err := Pull(testCtx(t), ba, r)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("Pull = %v, want %v", err, tc.want)
			}
			if after := snapshot(t, r); after != before {
				t.Fatalf("replica changed: %s, was %s", after, before)
			}
			if headOf(t, rb) != peerHead {
				t.Fatal("peer's log changed")
			}
		})
	}
}

func headOf(t *testing.T, s Source) string {
	t.Helper()
	h, err := s.Head()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Encode())
}

func TestTamperedEntry(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(*kololog.Entry)
	}{
		{"ciphertext", func(e *kololog.Entry) { e.Ciphertext[40] ^= 1 }},
		{"record", func(e *kololog.Entry) { e.Record[len(e.Record)-1] ^= 1 }},
		{"key", func(e *kololog.Entry) { e.Key[0] ^= 1 }},
		{"ciphertext dropped", func(e *kololog.Entry) { e.Ciphertext = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			l := ownLog(t, a, 4)
			a.srv.Offer(tamper{Source: l, entry: func(i uint64, e *kololog.Entry) {
				if i == 2 {
					tc.fn(e)
				}
			}})
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			before := snapshot(t, r)
			err := Pull(testCtx(t), ba, r)
			if !errors.Is(err, ErrInvalid) || !errors.Is(err, kololog.ErrBadEntry) {
				t.Fatalf("Pull = %v, want ErrInvalid wrapping kololog.ErrBadEntry", err)
			}
			if after := snapshot(t, r); after != before {
				t.Fatalf("replica changed: %s, was %s", after, before)
			}
		})
	}
}

func TestTamperedHead(t *testing.T) {
	a, b := newPeer(t), newPeer(t)
	other, err := a.st.Create(a.id)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherHead, err := other.Head()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		fn   func(*kololog.Head)
		want error
	}{
		{"root", func(h *kololog.Head) { h.Root[0] ^= 1 }, kololog.ErrBadHeadSignature},
		{"size", func(h *kololog.Head) { h.Size++ }, kololog.ErrBadHeadSignature},
		{"signature", func(h *kololog.Head) { h.Signature[0] ^= 1 }, kololog.ErrBadHeadSignature},
		{"other log", func(h *kololog.Head) { *h = otherHead }, kololog.ErrWrongLogID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			l := ownLog(t, a, 3)
			a.srv.Offer(tamper{Source: l, head: tc.fn})
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			before := snapshot(t, r)
			err := Pull(testCtx(t), ba, r)
			if !errors.Is(err, ErrInvalid) || !errors.Is(err, tc.want) {
				t.Fatalf("Pull = %v, want ErrInvalid wrapping %v", err, tc.want)
			}
			if after := snapshot(t, r); after != before {
				t.Fatalf("replica changed: %s, was %s", after, before)
			}
		})
	}
}

func TestReplayOldHead(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	old, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	appendN(t, l, 2)
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, r)
	a.srv.Offer(tamper{Source: l, head: func(h *kololog.Head) { *h = old }})
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatalf("Pull of an old head = %v", err)
	}
	if after := snapshot(t, r); after != before {
		t.Fatalf("replica changed: %s, was %s", after, before)
	}
}

func frame(n uint32, payload []byte) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, n), payload...)
}

func wire(m message) []byte {
	p := encode(m)
	return frame(uint32(len(p)), p)
}

func TestTruncatedStream(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(st *kolotransport.Stream)
	}{
		{"no answer", func(*kolotransport.Stream) {}},
		{"half a length", func(st *kolotransport.Stream) { st.Write([]byte{9, 0}) }},
		{"half a message", func(st *kolotransport.Stream) { st.Write(frame(100, make([]byte, 10))) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			a.srv = nil
			ba, ab := connect(t, b, a, nil)
			rawServe(t, ab, func(st *kolotransport.Stream) {
				if _, err := readMsg(st, true); err != nil {
					t.Error(err)
				}
				tc.send(st)
			})
			_, err := FetchHeader(testCtx(t), ba, a.id.PublicKey(), kololog.LogID{1})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("FetchHeader = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestOversizedMessage(t *testing.T) {
	t.Run("from the server", func(t *testing.T) {
		checkGoroutines(t)
		a, b := newPeer(t), newPeer(t)
		a.srv = nil
		ba, ab := connect(t, b, a, nil)
		rawServe(t, ab, func(st *kolotransport.Stream) {
			readMsg(st, true)
			st.Write(frame(MaxMessageSize+1, make([]byte, 1000)))
		})
		_, err := FetchHeader(testCtx(t), ba, a.id.PublicKey(), kololog.LogID{1})
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("FetchHeader = %v, want ErrTooLarge", err)
		}
	})
	t.Run("from the client", func(t *testing.T) {
		checkGoroutines(t)
		a, b := newPeer(t), newPeer(t)
		ba, _ := connect(t, b, a, nil)
		st := rawStream(t, ba)
		st.Write(frame(MaxMessageSize+1, make([]byte, 1000)))
		got := readAll(t, st)
		if want := wire(message{typ: tError, code: codeTooLarge}); !bytes.Equal(got, want) {
			t.Fatalf("answer %x, want %x", got, want)
		}
	})
}

func readAll(t *testing.T, st *kolotransport.Stream) []byte {
	t.Helper()
	st.SetReadDeadline(time.Now().Add(2 * timeout))
	b, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNotFoundLooksTheSame(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	var mu sync.Mutex
	asked := make(map[kololog.LogID]int)
	var denied, panics kololog.LogID
	a.srv = NewServer(func(_, _ ed25519.PublicKey, id kololog.LogID) Access {
		mu.Lock()
		asked[id]++
		mu.Unlock()
		switch id {
		case denied:
			return NoAccess
		case panics:
			panic("app bug")
		}
		return Keys
	})
	denied = ownLog(t, a, 2).ID()
	panics = ownLog(t, a, 2).ID()
	open := ownLog(t, a, 2).ID()
	held, err := a.st.Create(a.id)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	appendN(t, held, 2)
	ba, _ := connect(t, b, a, nil)

	type name struct {
		owner ed25519.PublicKey
		id    kololog.LogID
	}
	alice := a.id.PublicKey()
	names := map[string]name{
		"unauthorized": {alice, denied}, "authorize panics": {alice, panics}, "not offered": {alice, held.ID()},
		"missing": {alice, kololog.LogID{7}}, "offered ID of another owner": {b.id.PublicKey(), open},
	}
	var first []byte
	for name, n := range names {
		owner, id := n.owner, n.id
		st := rawStream(t, ba)
		st.Write(wire(headReq(owner, id)))
		got := readAll(t, st)
		if first == nil {
			first = got
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("%s: answer %x differs from %x", name, got, first)
		}
		if _, err := FetchHeader(testCtx(t), ba, owner, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: FetchHeader = %v, want ErrNotFound", name, err)
		}
		mu.Lock()
		n := asked[id]
		mu.Unlock()
		if n != 2 {
			t.Fatalf("%s: authorize asked %d times, want 2", name, n)
		}
	}
}

func TestTooManyStreams(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 2)
	cfg := &kolosecure.Config{Transport: &kolotransport.Config{MaxIncomingStreams: 2 * MaxStreams}}
	ba, _ := connect(t, b, a, cfg)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	var held []*kolotransport.Stream
	for range MaxStreams {
		st := rawStream(t, ba)
		st.Write(wire(headReq(l.Header().LogKey, l.ID())))
		if m, err := readMsg(st, false); err != nil || m.typ != tHead {
			t.Fatalf("held stream: %v, type %d", err, m.typ)
		}
		held = append(held, st)
	}
	before := a.srv.Stats().BytesSent
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, ErrBusy) {
		t.Fatalf("Pull = %v, want ErrBusy", err)
	}
	// The refusal's bytes count, the refused stream does not; the add follows the write, so poll briefly.
	busy := uint64(len(wire(message{typ: tError, code: codeBusy})))
	for deadline := time.Now().Add(2 * time.Second); a.srv.Stats().BytesSent-before < busy && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if s := a.srv.Stats(); s.BytesSent-before != busy || s.ActiveStreams != MaxStreams {
		t.Fatalf("after a refusal: %d more bytes and %d streams, want %d and %d", s.BytesSent-before, s.ActiveStreams, busy, MaxStreams)
	}
	for _, st := range held {
		end(st)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := Pull(testCtx(t), ba, r)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrBusy) || time.Now().After(deadline) {
			t.Fatalf("Pull after the streams ended = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	sameEntries(t, r, l)
}

func TestReadTimeout(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		checkGoroutines(t)
		a, b := newPeer(t), newPeer(t)
		ba, _ := connect(t, b, a, nil)
		st := rawStream(t, ba)
		start := time.Now()
		st.Write(frame(10, nil))
		if got := readAll(t, st); len(got) != 0 {
			t.Fatalf("answer %x to a stalled request", got)
		}
		if d := time.Since(start); d < timeout {
			t.Fatalf("server gave up after %v, before the %v timeout", d, timeout)
		}
	})
	t.Run("client", func(t *testing.T) {
		checkGoroutines(t)
		a, b := newPeer(t), newPeer(t)
		a.srv = nil
		ba, ab := connect(t, b, a, nil)
		rawServe(t, ab, func(st *kolotransport.Stream) {
			readMsg(st, true)
			readMsg(st, true) // wait, never answer
		})
		start := time.Now()
		_, err := FetchHeader(testCtx(t), ba, a.id.PublicKey(), kololog.LogID{1})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("FetchHeader = %v, want ErrTimeout", err)
		}
		if d := time.Since(start); d < timeout {
			t.Fatalf("client gave up after %v, before the %v timeout", d, timeout)
		}
	})
}

func TestPullContext(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	ba, ab := connect(t, b, a, nil)
	rawServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		readMsg(st, true) // never answer
	})
	ctx, cancel := context.WithTimeout(testCtx(t), timeout/10)
	defer cancel()
	start := time.Now()
	_, err := FetchHeader(ctx, ba, a.id.PublicKey(), kololog.LogID{1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("FetchHeader = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d >= timeout {
		t.Fatalf("returned after %v, not when ctx ended", d)
	}
}

func TestBadProofIsNotDivergence(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2)
	a.srv.Offer(tamper{Source: l, proof: func(p *kololog.ConsistencyProof) {
		if len(p.Path) > 0 {
			p.Path[0][0] ^= 1
		}
	}})
	before := snapshot(t, r)
	err := Pull(testCtx(t), ba, r)
	if !errors.Is(err, ErrInvalid) || !errors.Is(err, kololog.ErrBadProof) || errors.Is(err, ErrDiverged) {
		t.Fatalf("Pull = %v, want ErrInvalid wrapping kololog.ErrBadProof", err)
	}
	if after := snapshot(t, r); after != before {
		t.Fatalf("replica changed: %s, was %s", after, before)
	}
}

func TestWithdraw(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	st := rawStream(t, ba)
	st.Write(wire(headReq(l.Header().LogKey, l.ID())))
	if m, err := readMsg(st, false); err != nil || m.typ != tHead {
		t.Fatalf("HEAD: %v, type %d", err, m.typ)
	}
	a.srv.Withdraw(l.Header().LogKey, l.ID())
	st.Write(wire(message{typ: tProofReq, a: 1, b: 3}))
	if got, want := readAll(t, st), wire(message{typ: tError, code: codeNotFound}); !bytes.Equal(got, want) {
		t.Fatalf("request after Withdraw: answer %x, want %x", got, want)
	}
	if _, err := FetchHeader(testCtx(t), ba, a.id.PublicKey(), l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FetchHeader after Withdraw = %v, want ErrNotFound", err)
	}
}

func TestUnknownAccessIsNoAccess(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Access(7) })
	l := ownLog(t, a, 1)
	ba, _ := connect(t, b, a, nil)
	if _, err := FetchHeader(testCtx(t), ba, a.id.PublicKey(), l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FetchHeader = %v, want ErrNotFound", err)
	}
}

func TestServerRejectsBadRanges(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	for _, req := range []message{
		{typ: tEntriesReq, a: 2, b: 1},
		{typ: tEntriesReq, a: 0, b: 3},
		{typ: tStateReq, a: 1, b: 3},
		{typ: tProofReq, a: 0, b: 4},
		{typ: tProofReq, a: 2, b: 1},
		headReq(l.Header().LogKey, l.ID()),
	} {
		st := rawStream(t, ba)
		st.Write(wire(headReq(l.Header().LogKey, l.ID())))
		readMsg(st, false)
		st.Write(wire(req))
		if got, want := readAll(t, st), wire(message{typ: tError, code: codeProtocol}); !bytes.Equal(got, want) {
			t.Fatalf("request %+v: answer %x, want %x", req, got, want)
		}
	}
}

func TestClientRejectsBadState(t *testing.T) {
	key := bytes.Repeat([]byte{1}, keySize)
	for name, resp := range map[string]message{
		"no progress":     {typ: tState, a: 0},
		"past the range":  {typ: tState, a: 3},
		"item past next":  {typ: tState, a: 1, items: []item{{index: 1, key: key}}},
		"unexpected type": {typ: tProof, proof: []byte{0}},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			c.srv = nil
			l := ownLog(t, a, 2)
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			if err := Pull(testCtx(t), ba, r); err != nil {
				t.Fatal(err)
			}
			h, _ := l.Head()
			bc, cb := connect(t, b, c, nil)
			rawServe(t, cb, func(st *kolotransport.Stream) {
				readMsg(st, true)
				st.Write(wire(message{typ: tHead, head: h.Encode(), header: l.Header().Encode()}))
				readMsg(st, true)
				st.Write(wire(resp))
			})
			if err := Pull(testCtx(t), bc, r); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Pull = %v, want ErrProtocol", err)
			}
		})
	}
}

// infoSource has entries with the flags info and counts the entries it is asked about; it holds no data.
type infoSource struct {
	Source
	info   kololog.EntryInfo
	keyErr error
	asked  *int
}

func (s infoSource) EntryInfo(uint64) (kololog.EntryInfo, error) {
	*s.asked++
	return s.info, nil
}

func (s infoSource) Key(uint64) (kololog.EntryKey, error) { return nil, s.keyErr }

func TestStateLooksAtMostMaxScan(t *testing.T) {
	asked := 0
	m, code := state(infoSource{asked: &asked}, true, 5, 1<<40)
	if code != 0 || m.a != 5+maxScan || len(m.items) != 0 || asked != maxScan {
		t.Fatalf("state = next %d, %d items, code %d after %d entries; want next %d", m.a, len(m.items), code, asked, 5+maxScan)
	}
}

// A key that is gone since EntryInfo said it was there is left out; the entry was deleted meanwhile.
func TestStateSkipsKeyDeletedMeanwhile(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code uint64
	}{{kololog.ErrDeleted, 0}, {errors.New("disk error"), codeBusy}} {
		asked := 0
		m, code := state(infoSource{info: kololog.EntryInfo{Keyed: true}, keyErr: tc.err, asked: &asked}, true, 0, 2)
		if code != tc.code || len(m.items) != 0 || (code == 0 && m.a != 3) {
			t.Fatalf("%v: state = next %d, %d items, code %d; want code %d", tc.err, m.a, len(m.items), code, tc.code)
		}
	}
}

// A peer that answers with another owner's header, or another log's, is caught by the header check.
func TestFetchHeaderWrongOwner(t *testing.T) {
	for name, other := range map[string]bool{"other owner": true, "other log": false} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			l := ownLog(t, a, 1)
			served := ownLog(t, a, 1)
			if other {
				served = ownLog(t, c, 1)
			}
			c.srv = nil
			h, _ := served.Head()
			bc, cb := connect(t, b, c, nil)
			rawServe(t, cb, func(st *kolotransport.Stream) {
				readMsg(st, true)
				st.Write(wire(message{typ: tHead, head: h.Encode(), header: served.Header().Encode()}))
			})
			_, err := FetchHeader(testCtx(t), bc, a.id.PublicKey(), l.ID())
			if !errors.Is(err, ErrInvalid) || !errors.Is(err, kololog.ErrBadLogHeader) {
				t.Fatalf("FetchHeader = %v, want ErrInvalid wrapping kololog.ErrBadLogHeader", err)
			}
		})
	}
}

func TestServeContext(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	srv := a.srv
	a.srv, b.srv = nil, nil
	_, ab := connect(t, b, a, nil)
	ctx, cancel := context.WithCancel(testCtx(t))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ab) }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve = %v, want context.Canceled", err)
	}
}

// bigAppend appends n entries of 1.5 MiB: two fit in a message of MaxMessageSize, but an answer holds one.
func bigAppend(t *testing.T, l *kolostore.Log, n int) {
	t.Helper()
	big := make([]byte, 1500<<10)
	for i := range n {
		big[0] = byte(i)
		if _, err := l.Append(big); err != nil {
			t.Fatal(err)
		}
	}
}

// interrupted makes b's replica of a's 7-entry log l stop after 4 entries, with the head of size 7 as its target.
func interrupted(t *testing.T, a, b *peer, l *kolostore.Log) (*kolosecure.Conn, *kolostore.Replica) {
	t.Helper()
	a.srv.Offer(tamper{Source: l, entry: func(i uint64, e *kololog.Entry) {
		if i >= 4 && e.Ciphertext != nil {
			e.Ciphertext[0] ^= 1
		}
	}})
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Pull = %v, want ErrInvalid", err)
	}
	if th, _, ok := r.Target(); r.Len() != 4 || !ok || th.Size != 7 {
		t.Fatalf("Len %d, target %v of size %d; want 4 entries toward 7", r.Len(), ok, th.Size)
	}
	a.srv.Offer(l)
	return ba, r
}

func TestResumeAfterOwnerMovesOn(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 0)
	bigAppend(t, l, 7)
	ba, r := interrupted(t, a, b, l)
	r.Close()
	r, err := b.st.OpenReplica(a.id.PublicKey(), l.ID(), nil) // a restart in the middle
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	appendN(t, l, 2)
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

func TestPeerBehindTarget(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, a, 0)
	bigAppend(t, l, 5)
	// c holds the first 5 entries: past what b will hold, short of b's target.
	ca, _ := connect(t, c, a, nil)
	rc := replica(t, c, ca, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ca, rc); err != nil {
		t.Fatal(err)
	}
	c.srv.Offer(rc)
	bigAppend(t, l, 2)
	ba, r := interrupted(t, a, b, l)
	bc, _ := connect(t, b, c, nil)
	before := snapshot(t, r)
	if err := Pull(testCtx(t), bc, r); err != nil {
		t.Fatalf("Pull from a peer behind the target = %v, want nil", err)
	}
	if after := snapshot(t, r); after != before {
		t.Fatalf("replica changed: %s, was %s", after, before)
	}
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

func TestRelayCannotForgeDivergence(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2)
	// A bad proof, then for the evidence request a record that differs from ours but is not signed.
	a.srv.Offer(tamper{Source: l,
		proof: func(p *kololog.ConsistencyProof) {
			if len(p.Path) > 0 {
				p.Path[0][0] ^= 1
			}
		},
		entry: func(i uint64, e *kololog.Entry) {
			if i == 2 {
				e.Record[len(e.Record)-1] ^= 1
			}
		}})
	err := Pull(testCtx(t), ba, r)
	if !errors.Is(err, ErrInvalid) || errors.Is(err, ErrDiverged) {
		t.Fatalf("Pull = %v, want ErrInvalid and not ErrDiverged", err)
	}
}

func TestConcurrentPullIsBusy(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := ownLog(t, a, 1)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	bc, cb := connect(t, b, c, nil)
	asked, release := make(chan struct{}), make(chan struct{})
	rawServe(t, cb, func(st *kolotransport.Stream) {
		readMsg(st, true)
		close(asked)
		select {
		case <-release:
		case <-time.After(2 * timeout):
		}
	})
	first := make(chan error, 1)
	go func() { first <- Pull(testCtx(t), bc, r) }()
	<-asked
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Pull = %v, want ErrBusy", err)
	}
	close(release)
	<-first
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatalf("Pull after the first ended = %v", err)
	}
	sameEntries(t, r, l)
}

func TestMarkerIndexMustMatch(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := ownLog(t, a, 2)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	e, err := l.Entry(1)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := l.Head()
	bc, cb := connect(t, b, c, nil)
	rawServe(t, cb, func(st *kolotransport.Stream) {
		readMsg(st, true)
		st.Write(wire(message{typ: tHead, head: h.Encode(), header: l.Header().Encode()}))
		readMsg(st, true)
		st.Write(wire(message{typ: tState, a: 2, items: []item{{index: 0, marker: e.Marker}}}))
	})
	if err := Pull(testCtx(t), bc, r); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Pull = %v, want ErrProtocol", err)
	}
	if _, err := r.Get(1); err != nil {
		t.Fatalf("entry 1 after a misplaced marker: %v", err)
	}
}

func TestStateAsksOnlyForMissingKeys(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	var mu sync.Mutex
	access := Keys
	a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access {
		mu.Lock()
		defer mu.Unlock()
		return access
	})
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	access = Ciphertext
	mu.Unlock()
	appendN(t, l, 2)
	// A deleted entry has no key, but no key is missing there either.
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	h, _ := l.Head()
	bc, cb := connect(t, b, c, nil)
	asked := make(chan []message, 1)
	rawServe(t, cb, func(st *kolotransport.Stream) {
		var got []message
		defer func() { asked <- got }()
		readMsg(st, true)
		st.Write(wire(message{typ: tHead, head: h.Encode(), header: l.Header().Encode()}))
		for {
			m, err := readMsg(st, true)
			if err != nil {
				return
			}
			got = append(got, m)
			st.Write(wire(message{typ: tState, a: m.b + 1}))
		}
	})
	if err := Pull(testCtx(t), bc, r); err != nil {
		t.Fatal(err)
	}
	got := <-asked
	want := []message{{typ: tStateReq, a: 0, b: 2}, {typ: tStateReq, a: 3, b: 4, keys: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("STATE requests %+v, want %+v", got, want)
	}
}

func TestForkBehindTarget(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	// Shared 5 entries; ra adds 5 (size 10), rb adds 3 others (size 8). b holds 7 of ra, with ra's head as target.
	_, ra, rb := forks(t, a.id, 5, 5, 3)
	ha, err := ra.Head()
	if err != nil {
		t.Fatal(err)
	}
	var first7 []kololog.Entry
	for i := range uint64(7) {
		e, err := ra.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		first7 = append(first7, e)
	}
	p, err := ra.ConsistencyProof(7, 10)
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.st.OpenReplica(a.id.PublicKey(), ra.ID(), ra.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Update(ha, p, first7); err != nil {
		t.Fatal(err)
	}
	c.srv.Offer(rb)
	bc, _ := connect(t, b, c, nil)
	before := snapshot(t, r)
	if err := Pull(testCtx(t), bc, r); !errors.Is(err, ErrDiverged) {
		t.Fatalf("Pull from a fork behind the target = %v, want ErrDiverged", err)
	}
	if after := snapshot(t, r); after != before {
		t.Fatalf("replica changed: %s, was %s", after, before)
	}
}

func TestOpenStreamTimeout(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	ba, _ := connect(t, b, a, nil)
	// a never accepts, so these use up the stream credit of kolo-transport's default limit.
	for range 16 {
		rawStream(t, ba).Write([]byte{0})
	}
	start := time.Now()
	_, err := FetchHeader(testCtx(t), ba, a.id.PublicKey(), kololog.LogID{1})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("FetchHeader = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d < timeout || d > 2*timeout {
		t.Fatalf("returned after %v, want about %v", d, timeout)
	}
}

func TestHeadOfAnotherKeyStopsThePull(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2)
	// c signs, with its own key, a head that names l's log ID.
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	h.LogKey = c.id.PublicKey()
	enc := h.Encode()
	if h.Signature, err = c.id.Sign(kololog.HeadContext, enc[:len(enc)-ed25519.SignatureSize]); err != nil {
		t.Fatal(err)
	}
	bc, cb := connect(t, b, c, nil)
	more := make(chan error, 1)
	rawServe(t, cb, func(st *kolotransport.Stream) {
		readMsg(st, true)
		st.Write(wire(message{typ: tHead, head: h.Encode(), header: l.Header().Encode()}))
		_, err := readMsg(st, true)
		more <- err
	})
	before := snapshot(t, r)
	if err := Pull(testCtx(t), bc, r); !errors.Is(err, ErrInvalid) || !errors.Is(err, kololog.ErrBadHeadSignature) {
		t.Fatalf("Pull = %v, want ErrInvalid wrapping kololog.ErrBadHeadSignature", err)
	}
	if err := <-more; err == nil {
		t.Fatal("the puller sent another request after a head of another key")
	}
	if after := snapshot(t, r); after != before {
		t.Fatalf("replica changed: %s, was %s", after, before)
	}
}

type counting struct {
	Source
	mu    sync.Mutex
	reads map[uint64]int
}

func (s *counting) Entry(i uint64) (kololog.Entry, error) {
	s.mu.Lock()
	s.reads[i]++
	s.mu.Unlock()
	return s.Source.Entry(i)
}

func TestOversizedEntryIsNeverRead(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 1)
	if _, err := l.Append(make([]byte, MaxMessageSize)); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 1)
	src := &counting{Source: l, reads: make(map[uint64]int)}
	a.srv.Offer(src)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Pull = %v, want ErrTooLarge", err)
	}
	st := rawStream(t, ba)
	st.Write(wire(headReq(l.Header().LogKey, l.ID())))
	readMsg(st, false)
	st.Write(wire(message{typ: tStateReq, a: 0, b: 2}))
	if m, err := readMsg(st, false); err != nil || m.typ != tState || m.a != 3 {
		t.Fatalf("STATE over the large entry: %+v, %v", m, err)
	}
	st.Write(wire(message{typ: tStateReq, a: 1, b: 1}))
	if m, err := readMsg(st, false); err != nil || m.typ != tState || m.a != 2 {
		t.Fatalf("STATE of the large entry alone: %+v, %v", m, err)
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if n := src.reads[1]; n != 0 {
		t.Fatalf("the large entry was read %d times", n)
	}
}

func TestPullCiphertextRefusesKeys(t *testing.T) {
	for name, keyed := range map[string]bool{"entries": true, "state": false} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			c.srv = nil
			l := ownLog(t, a, 2)
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			if !keyed {
				if err := PullCiphertext(testCtx(t), ba, r); err != nil {
					t.Fatal(err)
				}
			}
			e, err := l.Entry(0)
			if err != nil {
				t.Fatal(err)
			}
			h, _ := l.Head()
			bc, cb := connect(t, b, c, nil)
			rawServe(t, cb, func(st *kolotransport.Stream) {
				readMsg(st, true)
				st.Write(wire(message{typ: tHead, head: h.Encode(), header: l.Header().Encode()}))
				m, _ := readMsg(st, true)
				if m.keys {
					t.Error("PullCiphertext asked for keys")
				}
				if keyed {
					st.Write(wire(message{typ: tEntries, entries: []kololog.Entry{e}}))
				} else {
					st.Write(wire(message{typ: tState, a: 1, items: []item{{index: 0, key: e.Key}}}))
				}
			})
			before := snapshot(t, r)
			if err := PullCiphertext(testCtx(t), bc, r); !errors.Is(err, ErrProtocol) {
				t.Fatalf("PullCiphertext = %v, want ErrProtocol", err)
			}
			if after := snapshot(t, r); after != before {
				t.Fatalf("replica changed: %s, was %s", after, before)
			}
			for i := range r.Len() {
				if e, _ := r.Entry(i); e.Key != nil {
					t.Fatalf("entry %d has a key", i)
				}
			}
		})
	}
}

// A peer that has not seen a delete still sends the entry's key; the puller keeps the entry deleted.
func TestKeyForDeletedEntryIsDropped(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	ca, _ := connect(t, c, a, nil)
	rb := replica(t, b, ba, a.id.PublicKey(), l.ID())
	rc := replica(t, c, ca, a.id.PublicKey(), l.ID())
	if err := PullCiphertext(testCtx(t), ba, rb); err != nil {
		t.Fatal(err)
	}
	if err := Pull(testCtx(t), ca, rc); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	if err := PullCiphertext(testCtx(t), ba, rb); err != nil {
		t.Fatal(err)
	}
	c.srv.Offer(rc)
	bc, _ := connect(t, b, c, nil)
	if err := Pull(testCtx(t), bc, rb); err != nil {
		t.Fatal(err)
	}
	if _, err := rb.Get(1); !errors.Is(err, kololog.ErrDeleted) {
		t.Fatalf("Get(1) = %v, want kololog.ErrDeleted", err)
	}
	for _, i := range []uint64{0, 2} {
		if _, err := rb.Get(i); err != nil {
			t.Fatalf("Get(%d) = %v", i, err)
		}
	}
}

// A bad marker among good ones in one STATE answer fails the pull with ErrInvalid and applies none of them.
func TestBadMarkerAppliesNone(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(0, 1, 2); err != nil {
		t.Fatal(err)
	}
	var items []item
	for i := range uint64(3) {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			e.Marker[len(e.Marker)-1] ^= 1 // the signature
		}
		items = append(items, item{index: i, marker: e.Marker})
	}
	h, _ := l.Head()
	bc, cb := connect(t, b, c, nil)
	rawServe(t, cb, func(st *kolotransport.Stream) {
		readMsg(st, true)
		st.Write(wire(message{typ: tHead, head: h.Encode(), header: l.Header().Encode()}))
		readMsg(st, true)
		st.Write(wire(message{typ: tState, a: 3, items: items}))
	})
	if err := Pull(testCtx(t), bc, r); !errors.Is(err, ErrInvalid) || !errors.Is(err, kololog.ErrBadEntry) {
		t.Fatalf("Pull = %v, want ErrInvalid wrapping kololog.ErrBadEntry", err)
	}
	for i := range uint64(3) {
		if _, err := r.Get(i); err != nil {
			t.Fatalf("entry %d after a bad marker: %v", i, err)
		}
	}
	// The good markers still arrive from an honest peer.
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	for i := range uint64(3) {
		if _, err := r.Get(i); !errors.Is(err, kololog.ErrDeleted) {
			t.Fatalf("entry %d: %v, want kololog.ErrDeleted", i, err)
		}
	}
}

// squat makes a genuine log of m that reuses the log ID victim: its header and head are signed by m.
func squat(t *testing.T, m *koloid.Identity, victim kololog.LogID) *kololog.Log {
	t.Helper()
	fresh, err := kololog.New(m, kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	h0, err := fresh.Head()
	if err != nil {
		t.Fatal(err)
	}
	lh := kololog.LogHeader{LogKey: m.PublicKey(), LogID: victim, Encoding: fresh.Header().Encoding}
	fresh.Close()
	if lh.Signature, err = m.Sign(kololog.HeaderContext, lh.Encode()); err != nil {
		t.Fatal(err)
	}
	h := kololog.Head{LogKey: m.PublicKey(), LogID: victim, Root: h0.Root}
	if h.Signature, err = m.Sign(kololog.HeadContext, h.Encode()); err != nil {
		t.Fatal(err)
	}
	l, err := kololog.Restore(m, lh.Encode(), h.Encode(), kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// Two owners' logs with one log ID are two logs: offering or withdrawing one never touches the other.
func TestSameLogIDTwoOwners(t *testing.T) {
	checkGoroutines(t)
	a, b, m := newPeer(t), newPeer(t), newPeer(t)
	var mu sync.Mutex
	seen := make(map[string]bool)
	a.srv = NewServer(func(_, owner ed25519.PublicKey, _ kololog.LogID) Access {
		mu.Lock()
		seen[string(owner)] = true
		mu.Unlock()
		return Keys
	})
	l := ownLog(t, a, 3)
	sq := squat(t, m.id, l.ID())
	for i := range 2 {
		if _, err := sq.Append([]byte(fmt.Sprintf("squat %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.srv.Offer(sq); err != nil {
		t.Fatal(err)
	}
	ba, _ := connect(t, b, a, nil)
	check := func(owner ed25519.PublicKey, want getter, n uint64) {
		t.Helper()
		h, err := FetchHead(testCtx(t), ba, owner, l.ID())
		if err != nil {
			t.Fatal(err)
		}
		got, err := Fetch(testCtx(t), ba, h, 0, n-1)
		if err != nil {
			t.Fatal(err)
		}
		sameValues(t, got, want, 0, n-1)
	}
	check(a.id.PublicKey(), l, 3)
	check(m.id.PublicKey(), sq, 2)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
	mu.Lock()
	if !seen[string(a.id.PublicKey())] || !seen[string(m.id.PublicKey())] {
		t.Fatal("authorize was not told the owner")
	}
	mu.Unlock()

	a.srv.Withdraw(m.id.PublicKey(), l.ID())
	check(a.id.PublicKey(), l, 3)
	if _, err := FetchHead(testCtx(t), ba, m.id.PublicKey(), l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FetchHead of the withdrawn log = %v, want ErrNotFound", err)
	}
	a.srv.Offer(sq)
	a.srv.Withdraw(a.id.PublicKey(), l.ID())
	check(m.id.PublicKey(), sq, 2)
	if _, err := FetchHead(testCtx(t), ba, a.id.PublicKey(), l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FetchHead of the withdrawn log = %v, want ErrNotFound", err)
	}
}

type relabeled struct {
	Source
	h  kololog.LogHeader
	id kololog.LogID
}

func (s relabeled) ID() kololog.LogID         { return s.id }
func (s relabeled) Header() kololog.LogHeader { return s.h }

// Offer refuses a source whose header is not its owner's or names another log, so no source can take another owner's place.
func TestOfferChecksTheHeader(t *testing.T) {
	checkGoroutines(t)
	a, b, m := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	sq := squat(t, m.id, l.ID())
	other := ownLog(t, a, 1)
	claim := sq.Header()
	claim.LogKey = a.id.PublicKey() // mallory's signature under alice's key
	short := sq.Header()
	short.LogKey = short.LogKey[:31]
	for name, src := range map[string]Source{
		"header of another owner": relabeled{sq, claim, sq.ID()},
		"owner key of 31 bytes":   relabeled{sq, short, sq.ID()},
		"ID of another log":       relabeled{l, l.Header(), other.ID()},
	} {
		if err := a.srv.Offer(src); !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, kololog.ErrBadLogHeader) {
			t.Fatalf("%s: Offer = %v, want ErrInvalidArgument wrapping kololog.ErrBadLogHeader", name, err)
		}
	}
	ba, _ := connect(t, b, a, nil)
	h, err := FetchHead(testCtx(t), ba, a.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Fetch(testCtx(t), ba, h, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 0, 2)
}

func TestOfferAndWithdrawArguments(t *testing.T) {
	s := NewServer(nil)
	if err := s.Offer(nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Offer(nil) = %v", err)
	}
	owner := make(ed25519.PublicKey, ed25519.PublicKeySize)
	owner[0] = 1
	n, _ := nameOf(owner, kololog.LogID{1})
	s.logs[n] = nil
	// A short key never names a log, even one whose key it is a prefix of.
	s.Withdraw(nil, kololog.LogID{1})
	s.Withdraw(owner[:31], kololog.LogID{1})
	if len(s.logs) != 1 {
		t.Fatalf("%d logs offered after withdrawing short keys, want 1", len(s.logs))
	}
	s.Withdraw(owner, kololog.LogID{1})
	if len(s.logs) != 0 {
		t.Fatalf("%d logs offered after Withdraw, want 0", len(s.logs))
	}
}

// A message that takes longer than the timeout in all is read while MinProgress bytes of it arrive within each timeout,
// so a large answer over a slow path is not cut off while it makes progress.
func TestSlowMessageIsRead(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	ba, ab := connect(t, b, a, nil)
	const size = 100 << 10
	rawServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		b := frame(size, make([]byte, size))
		for len(b) > 0 {
			n := min(len(b), 25<<10)
			st.Write(b[:n])
			b = b[n:]
			time.Sleep(1100 * time.Millisecond) // 5 s in all, over the timeout
		}
	})
	st := rawStream(t, ba)
	if _, err := st.Write(frame(1, []byte{0})); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := readMsg(st, false)
	if errors.Is(err, ErrTimeout) || time.Since(start) < timeout {
		t.Fatalf("readMsg after %v = %v: cut off while it made progress", time.Since(start), err)
	}
}
