package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
)

func TestCatchUpFromEmpty(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 5)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

func TestCatchUpEmptyLog(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 0)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

func TestIncremental(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	for _, n := range []int{0, 4, 0, 1} {
		appendN(t, l, n)
		if err := Pull(testCtx(t), ba, r); err != nil {
			t.Fatal(err)
		}
		sameEntries(t, r, l)
	}
}

func TestCatchUpInChunks(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 0)
	big := make([]byte, 1500<<10)
	for i := range 7 {
		big[0] = byte(i)
		if _, err := l.Append(big); err != nil {
			t.Fatal(err)
		}
	}
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

func TestEntryTooLarge(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 1)
	if _, err := l.Append(make([]byte, MaxMessageSize)); err != nil {
		t.Fatal(err)
	}
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Pull = %v, want ErrTooLarge", err)
	}
	if r.Len() != 1 {
		t.Fatalf("Len %d, want the 1 entry before the large one", r.Len())
	}
}

func TestDeletePropagates(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, a, 4)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	deleted := func(r reader2) {
		t.Helper()
		if _, err := r.Get(1); !errors.Is(err, kololog.ErrDeleted) {
			t.Fatalf("Get(1) = %v, want ErrDeleted", err)
		}
		e, err := r.Entry(1)
		if err != nil || e.Marker == nil || e.Key != nil || e.Ciphertext != nil {
			t.Fatalf("entry 1 after delete: %v, marker %v, key %v", err, e.Marker != nil, e.Key != nil)
		}
		if _, err := r.Get(2); err != nil {
			t.Fatalf("Get(2) = %v", err)
		}
	}
	deleted(r)

	// A peer that pulls from the replica gets the marker with the entries.
	if err := b.srv.Offer(r); err != nil {
		t.Fatal(err)
	}
	cb, _ := connect(t, c, b, nil)
	rc := replica(t, c, cb, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), cb, rc); err != nil {
		t.Fatal(err)
	}
	deleted(rc)
}

type reader2 interface {
	Get(uint64) ([]byte, error)
	Entry(uint64) (kololog.Entry, error)
}

func TestKeysOnlyWhenAuthorized(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	var mu sync.Mutex
	access := Ciphertext
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
	for i := range uint64(3) {
		if _, err := r.Get(i); !errors.Is(err, kololog.ErrKeyUnavailable) {
			t.Fatalf("Get(%d) = %v, want ErrKeyUnavailable", i, err)
		}
	}
	mu.Lock()
	access = Keys
	mu.Unlock()
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

func TestReplicaServesThirdPeer(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, a, 5)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if err := b.srv.Offer(r); err != nil {
		t.Fatal(err)
	}
	cb, _ := connect(t, c, b, nil)
	rc := replica(t, c, cb, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), cb, rc); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, rc, l)
}

func TestManyLogsOneConnection(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	ba, _ := connect(t, b, a, nil)
	var ls []*kololog.LogID
	logs := make(map[kololog.LogID]reader)
	for i := range 8 {
		l := ownLog(t, a, i+1)
		id := l.ID()
		ls = append(ls, &id)
		logs[id] = l
	}
	reps := make(map[kololog.LogID]reader)
	errs := make(chan error, len(ls))
	var wg sync.WaitGroup
	for _, id := range ls {
		r := replica(t, b, ba, a.id.PublicKey(), *id)
		reps[*id] = r
		wg.Go(func() { errs <- Pull(testCtx(t), ba, r) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for id, l := range logs {
		sameEntries(t, reps[id], l)
	}
}

// TestThreeDevices is the multi-device chat model: each peer writes its own log and reads the other two.
func TestThreeDevices(t *testing.T) {
	checkGoroutines(t)
	peers := []*peer{newPeer(t), newPeer(t), newPeer(t)}
	logs := make([]*kolostore.Log, 3)
	for i, p := range peers {
		logs[i] = ownLog(t, p, 2+i)
	}
	conns := make(map[[2]int]*kolosecure.Conn)
	for i := range 3 {
		for j := i + 1; j < 3; j++ {
			conns[[2]int{i, j}], conns[[2]int{j, i}] = connect(t, peers[i], peers[j], nil)
		}
	}
	// reps[{i, j}] is peer i's replica of peer j's log.
	reps := make(map[[2]int]*kolostore.Replica)
	for k, conn := range conns {
		reps[k] = replica(t, peers[k[0]], conn, peers[k[1]].id.PublicKey(), logs[k[1]].ID())
	}
	for round := range 2 {
		for _, l := range logs {
			appendN(t, l, round+1)
		}
		errs := make(chan error, len(reps))
		var wg sync.WaitGroup
		for k, r := range reps {
			wg.Go(func() { errs <- Pull(testCtx(t), conns[k], r) })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		for k, r := range reps {
			sameEntries(t, r, logs[k[1]])
		}
	}
}

func TestInvalidArguments(t *testing.T) {
	ctx := context.Background()
	if err := Pull(ctx, nil, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Pull(nil) = %v", err)
	}
	if _, err := FetchHeader(ctx, nil, nil, kololog.LogID{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("FetchHeader(nil) = %v", err)
	}
	s := NewServer(nil)
	if err := s.Offer(nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Offer(nil) = %v", err)
	}
	if err := s.Serve(ctx, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Serve(nil) = %v", err)
	}
}

func TestResumeCatchUp(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 0)
	big := make([]byte, 1500<<10)
	for i := range 7 {
		big[0] = byte(i)
		if _, err := l.Append(big); err != nil {
			t.Fatal(err)
		}
	}
	var broken atomic.Bool
	broken.Store(true)
	a.srv.Offer(tamper{Source: l, entry: func(i uint64, e *kololog.Entry) {
		if i >= 4 && broken.Load() {
			e.Ciphertext[0] ^= 1
		}
	}})
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Pull = %v, want ErrInvalid", err)
	}
	if _, err := r.Head(); r.Len() != 4 || !errors.Is(err, kololog.ErrNoHead) {
		t.Fatalf("after the failed chunk: Len %d, Head error %v; want the 4 verified entries and no head", r.Len(), err)
	}
	broken.Store(false)
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

func TestDeleteOfLargeEntryPropagates(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 1)
	if _, err := l.Append(make([]byte, 3<<20)); err != nil {
		t.Fatal(err)
	}
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(1); !errors.Is(err, kololog.ErrDeleted) {
		t.Fatalf("Get(1) = %v, want ErrDeleted", err)
	}
}

func TestPullCiphertextStoresNoKey(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t) // a gives Keys
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := PullCiphertext(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2)
	if err := PullCiphertext(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	// What the store holds, read back after a reopen.
	r.Close()
	r, err := b.st.OpenReplica(a.id.PublicKey(), l.ID(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Len() != 5 {
		t.Fatalf("Len %d, want 5", r.Len())
	}
	for i := range r.Len() {
		e, err := r.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		if e.Key != nil {
			t.Fatalf("entry %d has a key", i)
		}
		if (i == 1) != (e.Marker != nil) {
			t.Fatalf("entry %d: marker %v", i, e.Marker != nil)
		}
	}
	if _, err := r.Get(0); !errors.Is(err, kololog.ErrKeyUnavailable) {
		t.Fatalf("Get(0) = %v, want ErrKeyUnavailable", err)
	}
}

func TestServerStats(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 4)
	ba, _ := connect(t, b, a, nil)

	// A raw stream: BytesSent is the sum of the frames read back, and the stream counts while open.
	st := rawStream(t, ba)
	var want uint64
	ask := func(req message) message {
		t.Helper()
		st.Write(wire(req))
		m, err := readMsg(st, false)
		if err != nil {
			t.Fatal(err)
		}
		want += uint64(len(wire(m)))
		return m
	}
	ask(headReq(l.Header().LogKey, l.ID()))
	missing := rawStream(t, ba)
	missing.Write(wire(headReq(a.id.PublicKey(), kololog.LogID{9})))
	want += uint64(len(readAll(t, missing))) // an ERROR answer counts too
	ask(message{typ: tProofReq, a: 1, b: 4})
	ask(message{typ: tEntriesReq, a: 0, b: 3, keys: true})
	ask(message{typ: tStateReq, a: 0, b: 3})
	// The ERROR stream ends on the server just after its answer, and each answer is counted just after it is written.
	for deadline := time.Now().Add(5 * time.Second); (a.srv.Stats().ActiveStreams > 1 || a.srv.Stats().BytesSent != want) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if s := a.srv.Stats(); s.BytesSent != want || s.ActiveStreams != 1 {
		t.Fatalf("Stats = %+v, want %d bytes and 1 stream", s, want)
	}
	end(st)
	waitIdle(t, a.srv)

	// A pull of the 4 entries sends at least their bytes.
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	before := a.srv.Stats().BytesSent
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	var entries uint64
	for i := range l.Len() {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		entries += uint64(len(e.Record) + len(e.Ciphertext) + len(e.Key))
	}
	if sent := a.srv.Stats().BytesSent - before; sent < entries {
		t.Fatalf("a pull sent %d bytes, less than the %d bytes of its entries", sent, entries)
	}
	waitIdle(t, a.srv)
}

// waitIdle waits until srv serves no stream; a stream ends on the server shortly after the client ends it.
func waitIdle(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for srv.Stats().ActiveStreams != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("ActiveStreams = %d, want 0", srv.Stats().ActiveStreams)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServerStatsConcurrentPulls(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	ba, _ := connect(t, b, a, nil)
	var reps []*kolostore.Replica
	for i := range 6 {
		l := ownLog(t, a, i+2)
		reps = append(reps, replica(t, b, ba, a.id.PublicKey(), l.ID()))
	}
	// The FetchHeader streams above end on the server after they end here; each pull below opens one stream.
	waitIdle(t, a.srv)
	stop := make(chan struct{})
	peak := make(chan int)
	go func() {
		most := 0
		for {
			select {
			case <-stop:
				peak <- most
				return
			default:
				most = max(most, a.srv.Stats().ActiveStreams)
			}
		}
	}()
	before := a.srv.Stats().BytesSent
	var wg sync.WaitGroup
	for _, r := range reps {
		wg.Go(func() {
			if err := Pull(testCtx(t), ba, r); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	close(stop)
	if most := <-peak; most < 1 || most > len(reps) {
		t.Fatalf("at most %d streams at once, want 1 to %d", most, len(reps))
	}
	if a.srv.Stats().BytesSent <= before {
		t.Fatal("BytesSent did not grow")
	}
	waitIdle(t, a.srv)
}

// countingBackend counts the value bytes its backend returns and the batches it commits, and fails commits while fail is set.
type countingBackend struct {
	kolostore.Backend
	read    atomic.Int64
	commits atomic.Int64
	fail    atomic.Bool
}

var errCommit = errors.New("injected commit failure")

func (b *countingBackend) NewBatch() kolostore.Batch { return &countingBatch{b.Backend.NewBatch(), b} }

type countingBatch struct {
	kolostore.Batch
	b *countingBackend
}

func (c *countingBatch) Commit() error {
	if c.b.fail.Load() {
		return errCommit
	}
	c.b.commits.Add(1)
	return c.Batch.Commit()
}

// countingPeer gives p a store on a countingBackend.
func countingPeer(t *testing.T, p *peer) *countingBackend {
	t.Helper()
	b := &countingBackend{Backend: kolostore.NewMemory()}
	p.st = kolostore.New(b)
	t.Cleanup(func() { p.st.Close() })
	return b
}

func (b *countingBackend) Get(key []byte) ([]byte, error) {
	v, err := b.Backend.Get(key)
	b.read.Add(int64(len(v)))
	return v, err
}

func (b *countingBackend) Scan(start, end []byte, reverse bool, limit int, fn func(key, value []byte) bool) error {
	return b.Backend.Scan(start, end, reverse, limit, func(k, v []byte) bool {
		b.read.Add(int64(len(v)))
		return fn(k, v)
	})
}

// A pull with nothing new reads markers and keys at most, never a ciphertext, on either side.
func TestIdlePullReadsNoCiphertext(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	backends := [2]*countingBackend{countingPeer(t, a), countingPeer(t, b)}
	l, err := a.st.Create(a.id)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	const size = 256 << 10
	for range 4 {
		if _, err := l.Append(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	a.srv.Offer(l)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if v, err := r.Get(3); err != nil || len(v) != size || r.Len() != 4 {
		t.Fatalf("after the first pull: %d entries, Get(3) = %d bytes, %v", r.Len(), len(v), err)
	}
	for _, c := range backends {
		c.read.Store(0)
	}
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	for i, c := range backends {
		if n := c.read.Load(); n >= size {
			t.Fatalf("peer %d read %d bytes from its store in an idle pull", i, n)
		}
	}
}

// The markers of one STATE answer are applied in one commit, and a failed commit applies none of them.
func TestMarkersCommitOncePerMessage(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	bb := countingPeer(t, b)
	l := ownLog(t, a, 300)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	var gone []uint64
	for i := uint64(0); i < 300; i += 3 {
		gone = append(gone, i)
	}
	if err := l.Delete(gone...); err != nil {
		t.Fatal(err)
	}
	bb.fail.Store(true)
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, errCommit) {
		t.Fatalf("Pull with failing commits = %v, want the commit error", err)
	}
	for _, i := range gone {
		if _, err := r.Get(i); err != nil {
			t.Fatalf("entry %d after a failed commit: %v", i, err)
		}
	}
	bb.fail.Store(false)
	bb.commits.Store(0)
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if n := bb.commits.Load(); n != 1 {
		t.Fatalf("%d markers took %d commits, want 1", len(gone), n)
	}
	for i := range uint64(300) {
		if _, err := r.Get(i); errors.Is(err, kololog.ErrDeleted) != (i%3 == 0) {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
}

// keyedReplica returns a replica of l's 3 entries in a counting store, holding the keys of entries 1 and 2 but not 0.
func keyedReplica(t *testing.T, l *kolostore.Log) (*kolostore.Replica, *countingBackend, []kololog.Entry) {
	t.Helper()
	p := &peer{}
	cb := countingPeer(t, p)
	r, err := p.st.OpenReplica(l.Header().LogKey, l.ID(), l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	var entries []kololog.Entry
	for i := range uint64(3) {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	held := slices.Clone(entries)
	held[0].Key = nil
	h, _ := l.Head()
	if err := r.Update(h, kololog.ConsistencyProof{OldSize: 3, NewSize: 3}, held); err != nil {
		t.Fatal(err)
	}
	return r, cb, entries
}

// A key equal to the one held stores nothing; only the missing key is committed.
func TestKeyAlreadyHeldStoresNothing(t *testing.T) {
	a := newPeer(t)
	l := ownLog(t, a, 3)
	r, cb, entries := keyedReplica(t, l)
	cb.commits.Store(0)
	m := message{typ: tState, a: 3}
	for i, e := range entries {
		m.items = append(m.items, item{index: uint64(i), key: e.Key})
	}
	if err := (&client{}).apply(r, m, 0, 3); err != nil {
		t.Fatal(err)
	}
	if n := cb.commits.Load(); n != 1 {
		t.Fatalf("%d commits, want 1 for the one missing key", n)
	}
	if _, err := r.Get(0); err != nil {
		t.Fatal(err)
	}
}

// A key other than the one held fails with ErrInvalid; markers of the answer stay applied, later keys are not added.
func TestKeyOtherThanHeldFails(t *testing.T) {
	a := newPeer(t)
	l := ownLog(t, a, 3)
	r, cb, entries := keyedReplica(t, l)
	before, err := r.Key(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(2); err != nil {
		t.Fatal(err)
	}
	e2, err := l.Entry(2)
	if err != nil {
		t.Fatal(err)
	}
	cb.commits.Store(0)
	m := message{typ: tState, a: 3, items: []item{{index: 1, key: entries[2].Key}, {index: 2, marker: e2.Marker}}}
	if err := (&client{}).apply(r, m, 0, 3); !errors.Is(err, ErrInvalid) || !errors.Is(err, kololog.ErrBadEntry) {
		t.Fatalf("apply = %v, want ErrInvalid wrapping kololog.ErrBadEntry", err)
	}
	if after, err := r.Key(1); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("key 1 changed: %v", err)
	}
	if _, err := r.Get(2); !errors.Is(err, kololog.ErrDeleted) {
		t.Fatalf("entry 2 = %v, want the marker applied", err)
	}
	if n := cb.commits.Load(); n != 1 {
		t.Fatalf("%d commits, want 1 for the marker", n)
	}

	// A bad key stops the answer: keys after it are not added, keys before it stay.
	m = message{typ: tState, a: 2, items: []item{{index: 0, key: entries[1].Key}, {index: 1, key: entries[1].Key}}}
	if err := (&client{}).apply(r, m, 0, 2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("apply = %v, want ErrInvalid", err)
	}
	if _, err := r.Get(0); !errors.Is(err, kololog.ErrKeyUnavailable) {
		t.Fatalf("entry 0 = %v, want no key", err)
	}
}

// An answer to a request for entries holds about 1 MiB, not as many as fit in 4 MiB, so a slow path delivers whole
// answers often; an entry larger than that still goes alone.
func TestEntriesAnswerIsFilledToAboutAMebibyte(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l, err := b.st.Create(b.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	sizes := []int{300 << 10, 300 << 10, 300 << 10, 300 << 10, 300 << 10, 3 << 20, 300 << 10}
	for _, n := range sizes {
		if _, err := l.Append(make([]byte, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	ab, _ := connect(t, a, b, nil)
	st := rawStream(t, ab)
	if _, err := writeMsg(st, headReq(b.id.PublicKey(), l.ID())); err != nil {
		t.Fatal(err)
	}
	if m, err := readMsg(st, false); err != nil || m.typ != tHead {
		t.Fatalf("head %v: %v", m.typ, err)
	}
	var got []int
	for start := uint64(0); start < uint64(len(sizes)); {
		req := message{typ: tEntriesReq, a: start, b: uint64(len(sizes)) - 1}
		if _, err := writeMsg(st, req); err != nil {
			t.Fatal(err)
		}
		m, err := readMsg(st, false)
		if err != nil || m.typ != tEntries || len(m.entries) == 0 {
			t.Fatalf("answer %+v: %v", m.typ, err)
		}
		bytes := 0
		for _, e := range m.entries {
			bytes += len(e.Ciphertext)
		}
		got = append(got, len(m.entries))
		if len(m.entries) > 1 && bytes > 1<<20+300<<10 {
			t.Fatalf("an answer of %d entries holds %d bytes", len(m.entries), bytes)
		}
		start += uint64(len(m.entries))
	}
	// 300 KiB entries: three to an answer (900 KiB plus overhead), then the 3 MiB entry alone, then the last.
	if len(got) < 4 || got[0] > 4 {
		t.Fatalf("entries per answer %v", got)
	}
}
