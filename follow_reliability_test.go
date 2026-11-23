package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	koloid "github.com/ciranda-dev/kolo-id"
	kolotransport "github.com/ciranda-dev/kolo-transport"
	"math"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
)

// tally follows the pulls of a Follower: the most at once, the most on one connection, the most answer bytes one held.
type tally struct {
	mu                                   sync.Mutex
	running, maxRunning, maxOnConn, held int
	onConn                               map[Conn]int
}

func (tl *tally) watch(f *Follower) {
	tl.onConn = map[Conn]int{}
	f.usePull(func(ctx context.Context, conn Conn, rep *kolostore.Replica, keysFrom uint64) (uint64, error) {
		tl.mu.Lock()
		tl.running++
		tl.onConn[conn]++
		tl.maxRunning, tl.maxOnConn = max(tl.maxRunning, tl.running), max(tl.maxOnConn, tl.onConn[conn])
		tl.mu.Unlock()
		var m PullMeter
		res, err := PullWith(ctx, conn, rep, &PullOptions{KeysFrom: keysFrom, Meter: &m})
		tl.mu.Lock()
		tl.running--
		tl.onConn[conn]--
		tl.held = max(tl.held, res.Stats.HeldMax)
		tl.mu.Unlock()
		return res.KeysFrom, err
	})
}

// stalled is a Source that holds every read of an entry from index at on until open is called, so a pull of it stops there.
type stalled struct {
	Source
	at      atomic.Uint64
	waiting atomic.Int32
	minRead atomic.Uint64 // the smallest index read since the last reset
	release chan struct{}
	once    sync.Once
}

func newStalled(src Source, at uint64) *stalled {
	s := &stalled{Source: src, release: make(chan struct{})}
	s.at.Store(at)
	s.minRead.Store(math.MaxUint64)
	return s
}

func (s *stalled) open() { s.once.Do(func() { close(s.release) }) }

func (s *stalled) Entry(i uint64) (kololog.Entry, error) {
	for {
		m := s.minRead.Load()
		if i >= m || s.minRead.CompareAndSwap(m, i) {
			break
		}
	}
	if i >= s.at.Load() {
		s.waiting.Add(1)
		<-s.release
		s.waiting.Add(-1)
	}
	return s.Source.Entry(i)
}

// ownSized is ownLog with n entries of size bytes, offered through the Source that offer returns.
func ownSized(t *testing.T, p *peer, n, size int, offer func(*kolostore.Log) Source) *kolostore.Log {
	t.Helper()
	l, err := p.st.Create(p.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	buf := make([]byte, size)
	for i := range n {
		binary.BigEndian.PutUint64(buf, uint64(i))
		if _, err := l.Append(buf); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.srv.Offer(offer(l)); err != nil {
		t.Fatal(err)
	}
	return l
}

func openPebbleStore(t *testing.T, dir string) *kolostore.Store {
	t.Helper()
	b, err := kolostore.OpenPebble(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(b)
	t.Cleanup(func() { st.Close() })
	return st
}

// A follower killed mid-pull and rebuilt from its Pebble directory resumes from the stored length and ends with the owner's entries, once each.
func TestFollowRestartOnPebble(t *testing.T) {
	checkGoroutines(t)
	const total, size = 4000, 1 << 10
	a, c := watchPeer(t, ServerOptions{}, nil), newPeer(t)
	var gate *stalled
	l := ownSized(t, a, total, size, func(l *kolostore.Log) Source {
		gate = newStalled(l, 3*total/4)
		return gate
	})
	dir := filepath.Join(t.TempDir(), "db")
	st := openPebbleStore(t, dir)
	conn, _ := connect(t, c, a, nil)
	t.Cleanup(gate.open)
	h, err := FetchHeader(testCtx(t), conn, pub(a), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := st.OpenReplica(pub(a), l.ID(), h)
	if err != nil {
		t.Fatal(err)
	}
	f := newFollowerT(t, nil)
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	r := follow(t, f, conn)
	waitFor(t, "the pull to stop at the gate", func() bool { return gate.waiting.Load() > 0 && rep.Len() > 0 })
	f.Close()
	<-r.done
	held := rep.Len()
	if held == 0 || held >= total {
		t.Fatalf("the pull stopped with %d of %d entries", held, total)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	gate.minRead.Store(math.MaxUint64)
	st = openPebbleStore(t, dir)
	ids, err := st.List()
	if err != nil || len(ids) != 1 || ids[0] != l.ID() {
		t.Fatalf("List = %v, %v", ids, err)
	}
	owner, isReplica, err := st.Owner(ids[0])
	if err != nil || !isReplica || !bytes.Equal(owner, pub(a)) {
		t.Fatalf("Owner = %x, %v, %v", owner, isReplica, err)
	}
	rep, err = st.OpenReplica(owner, ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Len() != held {
		t.Fatalf("reopened with %d entries, held %d", rep.Len(), held)
	}
	f = newFollowerT(t, nil)
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	conn, _ = connect(t, c, a, nil)
	t.Cleanup(gate.open)
	follow(t, f, conn)
	gate.open()
	waitLen(t, rep, total)
	sameLog(t, rep, l)
	if m := gate.minRead.Load(); m < held {
		t.Fatalf("the owner read entry %d again, the replica held %d", m, held)
	}
	if ids, err := st.List(); err != nil || len(ids) != 1 {
		t.Fatalf("List = %v, %v", ids, err)
	}
}

// A follower away while the owner appends 10,000 entries and deletes some, held and new, converges on reconnecting, markers applied.
func TestFollowLongOffline(t *testing.T) {
	checkGoroutines(t)
	a, c := watchPeer(t, ServerOptions{}, nil), newPeer(t)
	l := ownLog(t, a, 100)
	conn, _ := connect(t, c, a, nil)
	rep := replica(t, c, conn, pub(a), l.ID())
	f := newFollowerT(t, nil)
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	r := follow(t, f, conn)
	waitLen(t, rep, 100)
	conn.Close()
	<-r.done

	appendN(t, l, 10000)
	deleted := []uint64{3, 50, 99, 100, 5000, 10099}
	if err := l.Delete(deleted...); err != nil {
		t.Fatal(err)
	}
	conn, _ = connect(t, c, a, nil)
	follow(t, f, conn)
	waitLong(t, "the entries", func() bool { return rep.Len() == 10100 })
	waitLong(t, "the markers", func() bool {
		for _, i := range deleted {
			if info, err := rep.EntryInfo(i); err != nil || !info.Deleted {
				return false
			}
		}
		return true
	})
	sameLog(t, rep, l)
}

// 256 logs of 8 owners on 8 connections all arrive, with the pulls, the streams and the memory inside their bounds.
func TestFollowManyLogs(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts *FollowOptions
	}{{"defaults", nil}, {"pulls per connection", &FollowOptions{MaxPullsPerConn: 3}}} {
		t.Run(tc.name, func(t *testing.T) { manyLogs(t, tc.opts) })
	}
}

func manyLogs(t *testing.T, opts *FollowOptions) {
	checkGoroutines(t)
	const owners, perOwner, entries, size = 8, 32, 200, 512
	c := newPeer(t)
	f := newFollowerT(t, opts)
	o := f.opts
	var tl tally
	tl.watch(f)
	type pair struct {
		l   *kolostore.Log
		rep *kolostore.Replica
	}
	var pairs []pair
	var servers []*Server
	var conns []Conn
	for range owners {
		a := watchPeer(t, ServerOptions{}, nil)
		conn, _ := connect(t, c, a, nil)
		servers, conns = append(servers, a.srv), append(conns, conn)
		for range perOwner {
			l := ownSized(t, a, entries, size, func(l *kolostore.Log) Source { return l })
			rep := replica(t, c, conn, pub(a), l.ID())
			if err := f.Add(rep); err != nil {
				t.Fatal(err)
			}
			pairs = append(pairs, pair{l, rep})
		}
	}
	stop := make(chan struct{})
	var sampled sync.WaitGroup
	peak := make([]int, owners)
	sampled.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			for i, s := range servers {
				peak[i] = max(peak[i], s.Stats().ActiveStreams)
			}
		}
	})
	for _, conn := range conns {
		follow(t, f, conn)
	}
	for _, p := range pairs {
		waitLong(t, "the entries", func() bool { return p.rep.Len() == entries })
	}
	close(stop)
	sampled.Wait()
	for _, p := range pairs {
		sameLog(t, p.rep, p.l)
	}
	if tl.maxRunning < 2 || tl.maxRunning > o.MaxPulls || tl.maxOnConn > o.MaxPullsPerConn {
		t.Fatalf("most pulls at once %d (limit %d), on one connection %d (limit %d)", tl.maxRunning, o.MaxPulls, tl.maxOnConn, o.MaxPullsPerConn)
	}
	// One message is always admitted, so a pull may hold one answer of MaxMessageSize.
	if limit := max(6<<20, MaxMessageSize); tl.held > limit {
		t.Fatalf("a pull held %d bytes of answers, limit %d", tl.held, limit)
	}
	for i, s := range servers {
		if st := s.Stats(); peak[i] > MaxStreams || st.RefusedByLimit != 0 || st.AnswerBytes != 0 {
			t.Fatalf("server %d: %d streams at most (limit %d), %+v", i, peak[i], MaxStreams, st)
		}
	}
	f.mu.Lock()
	queued := len(f.events)
	f.mu.Unlock()
	if queued > 3*len(pairs) {
		t.Fatalf("%d events queued for %d logs", queued, len(pairs))
	}
	t.Logf("%d logs: %d pulls at once (limit %d), %d on one connection (limit %d), a pull held %d bytes, most streams on a server %v", len(pairs), tl.maxRunning, o.MaxPulls, tl.maxOnConn, o.MaxPullsPerConn, tl.held, peak)
}

// When the peer a pull runs from goes away mid-pull, another peer that holds the log finishes it.
func TestFollowPeerDisappearsMidPull(t *testing.T) {
	checkGoroutines(t)
	const total, size = 4000, 1 << 10
	a, b, c := watchPeer(t, ServerOptions{}, nil), watchPeer(t, ServerOptions{}, nil), newPeer(t)
	var gate *stalled
	l := ownSized(t, a, total, size, func(l *kolostore.Log) Source {
		gate = newStalled(l, math.MaxUint64)
		return gate
	})
	ba, _ := connect(t, b, a, nil)
	copyB := replica(t, b, ba, pub(a), l.ID())
	if err := Pull(testCtx(t), ba, copyB); err != nil {
		t.Fatal(err)
	}
	if err := b.srv.Offer(copyB); err != nil {
		t.Fatal(err)
	}
	ca, _ := connect(t, c, a, nil)
	cb, _ := connect(t, c, b, nil)
	t.Cleanup(gate.open)
	rep := replica(t, c, ca, pub(a), l.ID())
	f := newFollowerT(t, nil)
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	gate.at.Store(3 * total / 4)
	r := follow(t, f, ca)
	waitFor(t, "the pull from the owner to stop at the gate", func() bool { return gate.waiting.Load() > 0 && rep.Len() > 0 })
	ca.Close()
	<-r.done
	held := rep.Len()
	before := b.srv.Stats().BytesSent
	follow(t, f, cb)
	waitLen(t, rep, total)
	sameLog(t, rep, l)
	if sent := b.srv.Stats().BytesSent - before; sent < (total-held)*size {
		t.Fatalf("the other peer sent %d bytes for the %d entries missing", sent, total-held)
	}
}

// A follower on a Conn that is not a *kolosecure.Conn syncs, follows growth and applies delete markers.
func TestFollowRelayedConn(t *testing.T) {
	checkGoroutines(t)
	a, c := watchPeer(t, ServerOptions{}, nil), newPeer(t)
	l := ownLog(t, a, 50)
	ca, _ := connectRelayed(t, c, a)
	rep := replica(t, c, ca, pub(a), l.ID())
	f := newFollowerT(t, nil)
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, ca)
	waitLen(t, rep, 50)
	appendN(t, l, 10)
	waitLen(t, rep, 60)
	if err := l.Delete(2, 55); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 1)
	waitLen(t, rep, 61)
	waitFor(t, "the markers", func() bool {
		i2, err2 := rep.EntryInfo(2)
		i55, err55 := rep.EntryInfo(55)
		return err2 == nil && err55 == nil && i2.Deleted && i55.Deleted
	})
	sameLog(t, rep, l)
	if st, err := f.Status(pub(a), l.ID()); err != nil || st.Peers != 1 || st.Len != 61 {
		t.Fatalf("Status = %+v, %v", st, err)
	}
}

// A peer that holds a log at an old size and offers it does not keep the follower from the owner's growth.
func TestWithholdingPeerDoesNotBlock(t *testing.T) {
	checkGoroutines(t)
	a, w, c := watchPeer(t, ServerOptions{}, nil), watchPeer(t, ServerOptions{}, nil), newPeer(t)
	l := ownLog(t, a, 5)
	wa, _ := connect(t, w, a, nil)
	rw := replica(t, w, wa, pub(a), l.ID())
	if err := Pull(testCtx(t), wa, rw); err != nil {
		t.Fatal(err)
	}
	if err := w.srv.Offer(rw); err != nil {
		t.Fatal(err)
	}
	ca, _ := connect(t, c, a, nil)
	cw, _ := connect(t, c, w, nil)
	rep := replica(t, c, ca, pub(a), l.ID())
	f := newFollowerT(t, nil)
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, cw)
	follow(t, f, ca)
	waitLen(t, rep, 5)
	appendN(t, l, 10)
	waitLen(t, rep, 15)
	sameLog(t, rep, l)
	waitFor(t, "the status", func() bool {
		st, err := f.Status(pub(a), l.ID())
		return err == nil && st.Peers == 2 && st.Largest == 15 && st.Len == 15
	})
}

// Status reports what the connected peers offered, so a peer with an old copy makes the log look complete until the owner connects.
func TestStatusShowsStaleness(t *testing.T) {
	checkGoroutines(t)
	a, w, c := watchPeer(t, ServerOptions{}, nil), watchPeer(t, ServerOptions{}, nil), newPeer(t)
	l := ownLog(t, a, 5)
	wa, _ := connect(t, w, a, nil)
	rw := replica(t, w, wa, pub(a), l.ID())
	if err := Pull(testCtx(t), wa, rw); err != nil {
		t.Fatal(err)
	}
	if err := w.srv.Offer(rw); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 3)
	ca, _ := connect(t, c, a, nil)
	cw, _ := connect(t, c, w, nil)
	rep := replica(t, c, cw, pub(a), l.ID())
	f := newFollowerT(t, nil)
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, cw)
	waitLen(t, rep, 5)
	waitFor(t, "the status", func() bool {
		st, _ := f.Status(pub(a), l.ID())
		return st.Peers == 1 && !st.LastGrown.IsZero()
	})
	stale, _ := f.Status(pub(a), l.ID())
	if stale.Len != 5 || stale.Largest != 5 {
		t.Fatalf("Status = %+v, want 5 of 5", stale)
	}
	quiet(t, "the replica grew", 10*testGap, func() bool { return rep.Len() != 5 })
	follow(t, f, ca)
	waitLen(t, rep, 8)
	waitFor(t, "the status", func() bool {
		st, _ := f.Status(pub(a), l.ID())
		return st.Peers == 2 && st.Largest == 8 && st.LastGrown.After(stale.LastGrown)
	})
}

// A head offered during a pull of a larger one of another history is checked against the replica when the pull ends.
func TestTwoPeersSplitViewDetected(t *testing.T) {
	checkGoroutines(t)
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, ra, rb := forks(t, id, 3, 2, 3)
	pa, pb, c := watchPeer(t, ServerOptions{}, nil), watchPeer(t, ServerOptions{}, nil), newPeer(t)
	if err := pa.srv.Offer(ra); err != nil {
		t.Fatal(err)
	}
	if err := pb.srv.Offer(rb); err != nil {
		t.Fatal(err)
	}
	ca, _ := connect(t, c, pa, nil)
	cb, _ := connect(t, c, pb, nil)
	rep := replica(t, c, ca, id.PublicKey(), ra.ID())
	f := newFollowerT(t, nil)
	release := make(chan struct{})
	pull := f.pullWith
	f.usePull(func(ctx context.Context, conn Conn, rep *kolostore.Replica, keysFrom uint64) (uint64, error) {
		<-release
		return pull(ctx, conn, rep, keysFrom)
	})
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	waitPeers := func(n int) {
		waitFor(t, "the heads", func() bool {
			st, _ := f.Status(id.PublicKey(), ra.ID())
			return st.Peers == n
		})
	}
	follow(t, f, cb)
	waitPeers(1)
	follow(t, f, ca)
	waitPeers(2)
	close(release)
	ev := waitEvent(t, f, FollowDiverged)
	if !errors.Is(ev.Err, ErrDiverged) || !bytes.Equal(ev.Peer, pub(pa)) || ev.Len != 6 {
		t.Fatalf("event %+v", ev)
	}
	got := snapshot(t, rep)
	quiet(t, "the replica changed after the split view", 10*testGap, func() bool { return snapshot(t, rep) != got })
}

// 10,000 heads pushed by a peer start one pull, then the backoff holds the log back, and the follower keeps none of them.
func TestHeadFloodBounded(t *testing.T) {
	checkGoroutines(t)
	const batches, perBatch = 100, 100
	var s *scripted
	ready, read := make(chan struct{}), make(chan struct{})
	opts := &FollowOptions{RetryMin: 30 * time.Second, RetryMax: time.Minute}
	s = newScripted(t, 5, opts, func(n int, st *kolotransport.Stream) {
		if n > 1 {
			return
		}
		if m, err := readMsg(st, true); err != nil || m.typ != tWatchReq {
			return
		}
		<-ready
		h := signedHead(t, s.l).Encode()
		heads := make([][]byte, perBatch)
		for i := range heads {
			heads[i] = h
		}
		for range batches {
			if _, err := writeMsg(st, message{typ: tWatch, heads: heads}); err != nil {
				return
			}
		}
		// The follower ends the stream at the head that does not decode, after it read every head before it.
		_, _ = writeMsg(st, message{typ: tWatch, heads: [][]byte{bytes.Repeat([]byte{7}, 200)}})
		for {
			if _, err := readMsg(st, true); err != nil {
				close(read)
				return
			}
		}
	})
	flood := int64(batches * perBatch * len(signedHead(t, s.l).Encode()))
	live := func() int64 {
		var m runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	before := live()
	close(ready)
	select {
	case <-read:
	case <-time.After(30 * time.Second):
		t.Fatal("the follower did not read the flood")
	}
	if n := s.pulls.Load(); n != 1 {
		t.Fatalf("%d pulls for %d heads, want 1", n, batches*perBatch)
	}
	if grown := live() - before; grown > flood {
		t.Fatalf("the heap grew by %d bytes, the heads were %d", grown, flood)
	}
}

// A pull that fails once the replica holds the peer's head, with a marker still to come, is tried again.
func TestFollowRetriesAFailedPullAtTheHead(t *testing.T) {
	checkGoroutines(t)
	x := newFollow1(t, 5)
	f := newFollowerT(t, &FollowOptions{RetryMin: 100 * time.Millisecond, RetryMax: 100 * time.Millisecond})
	var calls atomic.Int32
	pull := f.pullWith
	f.usePull(func(ctx context.Context, conn Conn, rep *kolostore.Replica, keysFrom uint64) (uint64, error) {
		if calls.Add(1) == 1 {
			_, err := PullWith(ctx, conn, rep, nil)
			if err == nil {
				err = x.l.Delete(1)
			}
			return keysFrom, errors.Join(ErrTimeout, err)
		}
		return pull(ctx, conn, rep, keysFrom)
	})
	if err := f.Add(x.rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, x.conn)
	waitFor(t, "the marker", func() bool {
		info, err := x.rep.EntryInfo(1)
		return err == nil && info.Deleted
	})
	quiet(t, "a third pull", 10*testGap, func() bool { return calls.Load() > 2 })
	sameLog(t, x.rep, x.l)
}

// waitLong is waitFor for work that takes long under the race detector.
func waitLong(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(60 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// A WATCH of more heads than a server sends in one is a protocol error, so a peer cannot make the follower verify thousands.
func TestFollowWatchOverBatchEnds(t *testing.T) {
	checkGoroutines(t)
	var s *scripted
	ready, ended := make(chan struct{}), make(chan struct{})
	s = newScripted(t, 5, nil, watchScript(t, func() [][]byte {
		<-ready
		h := signedHead(t, s.l).Encode()
		heads := make([][]byte, watchBatch+1)
		for i := range heads {
			heads[i] = h
		}
		return heads
	}, ended))
	close(ready)
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the follower kept the watch stream")
	}
	if n := s.pulls.Load(); n != 0 {
		t.Fatalf("%d pulls from a WATCH over the batch", n)
	}
}

// A head the peer already offered is not verified again.
func TestFollowVerifiesAHeadOncePerPeer(t *testing.T) {
	checkGoroutines(t)
	var s *scripted
	ready, ended := make(chan struct{}), make(chan struct{})
	s = newScripted(t, 5, nil, watchScript(t, func() [][]byte {
		<-ready
		h := signedHead(t, s.l).Encode()
		heads := make([][]byte, watchBatch-1)
		for i := range heads {
			heads[i] = h
		}
		return append(heads, bytes.Repeat([]byte{7}, 200)) // ends the watch once the heads before it are read
	}, ended))
	var verified atomic.Int32
	s.f.useVerify(func(pub ed25519.PublicKey, id kololog.LogID, h kololog.Head) (kololog.VerifiedHead, error) {
		verified.Add(1)
		return kololog.VerifyHead(pub, id, h)
	})
	close(ready)
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the follower kept the watch stream")
	}
	if n := verified.Load(); n != 1 {
		t.Fatalf("%d signature checks for %d equal heads, want 1", n, watchBatch-1)
	}
}
