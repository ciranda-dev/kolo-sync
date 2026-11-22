package kolosync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-sync/internal/netsim"
)

func allowAll(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Keys }

// limited returns a peer that serves a log of entries of the given sizes with opts.
func limited(t *testing.T, opts *ServerOptions, sizes []int) (*peer, *kolostore.Log) {
	t.Helper()
	a := newPeer(t)
	srv, err := NewServerWith(allowAll, opts)
	if err != nil {
		t.Fatal(err)
	}
	a.srv = srv
	l := sizedLog(t, a, sizes)
	if err := srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	return a, l
}

// dial is a new peer on its own connection to a: it opens a stream and sends HEAD_REQ. It returns the stream and the
// first answer, a HEAD or the ERROR that refused the stream.
func dial(t *testing.T, a *peer, l *kolostore.Log) (*kolotransport.Stream, message) {
	t.Helper()
	conn, _ := connect(t, newPeer(t), a, nil)
	st := rawStream(t, conn)
	if _, err := writeMsg(st, headReq(a.id.PublicKey(), l.ID())); err != nil {
		t.Fatal(err)
	}
	m, err := readMsg(st, false)
	if err != nil {
		t.Fatal(err)
	}
	return st, m
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestNewServerWith(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts *ServerOptions
		ok   bool
	}{
		{"nil", nil, true},
		{"zero", &ServerOptions{}, true},
		{"set", &ServerOptions{MaxTotalStreams: 1, MaxAnswerBytes: 2 * MaxMessageSize}, true},
		{"negative streams", &ServerOptions{MaxTotalStreams: -1}, false},
		{"negative bytes", &ServerOptions{MaxAnswerBytes: -1}, false},
		{"bytes below one largest answer", &ServerOptions{MaxAnswerBytes: 2*MaxMessageSize - 1}, false},
		{"watched set", &ServerOptions{MaxWatched: maxWatchItems, WatchGap: 10 * time.Millisecond}, true},
		{"gap of a minute", &ServerOptions{WatchGap: time.Minute}, true},
		{"negative watched", &ServerOptions{MaxWatched: -1}, false},
		{"watched below one request", &ServerOptions{MaxWatched: maxWatchItems - 1}, false},
		{"negative gap", &ServerOptions{WatchGap: -time.Millisecond}, false},
		{"gap below 10 ms", &ServerOptions{WatchGap: 9 * time.Millisecond}, false},
	} {
		s, err := NewServerWith(allowAll, tc.opts)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrInvalidArgument)) || (err == nil) != (s != nil) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	s := NewServer(allowAll)
	if s.limits.MaxTotalStreams != DefaultMaxTotalStreams || s.limits.MaxAnswerBytes != DefaultMaxAnswerBytes ||
		s.limits.MaxWatched != DefaultMaxWatched || s.limits.WatchGap != DefaultWatchGap {
		t.Fatalf("defaults %+v", s.limits)
	}
}

// Streams over many connections of hostile peers stop at MaxTotalStreams, the rest are answered busy, and a slot a
// peer gives back is used again.
func TestServerTotalStreamCap(t *testing.T) {
	checkGoroutines(t)
	const cap = 5
	a, l := limited(t, &ServerOptions{MaxTotalStreams: cap}, []int{100, 100})
	var held []*kolotransport.Stream
	busy := 0
	for range 3 * cap {
		st, m := dial(t, a, l)
		switch {
		case m.typ == tHead:
			held = append(held, st)
		case m.typ == tError && m.code == codeBusy:
			busy++
		default:
			t.Fatalf("answer %+v", m)
		}
	}
	if len(held) != cap || busy != 2*cap {
		t.Fatalf("%d streams served and %d refused, want %d and %d", len(held), busy, cap, 2*cap)
	}
	if s := a.srv.Stats(); s.ActiveStreams != cap || s.RefusedByLimit != uint64(2*cap) {
		t.Fatalf("stats %+v", s)
	}
	end(held[0])
	waitFor(t, "a slot to be free", func() bool { return a.srv.taken.Load() == cap-1 })
	if st, m := dial(t, a, l); m.typ != tHead {
		t.Fatalf("after a slot was given back: %+v", m)
	} else {
		held = append(held, st)
	}
	for _, st := range held {
		end(st)
	}
	waitFor(t, "every slot to be free", func() bool { return a.srv.taken.Load() == 0 && a.srv.Stats().ActiveStreams == 0 })
}

// Streams that ask for answers and never read hold at most MaxAnswerBytes between them, the others are answered busy
// before the log is read, and the memory is given back when the peers go.
func TestServerAnswerBytesCap(t *testing.T) {
	for _, mode := range []string{"stream", "entries"} {
		t.Run(mode, func(t *testing.T) {
			checkGoroutines(t)
			const limit = 2 * MaxMessageSize
			a, l := limited(t, &ServerOptions{MaxAnswerBytes: limit}, repeat(256<<10, 16))
			size := l.Len()
			var sts []*kolotransport.Stream
			for range 10 {
				st, m := dial(t, a, l)
				if m.typ != tHead {
					t.Fatalf("answer %+v", m)
				}
				req := message{typ: tStreamReq, size: size, keys: true, credit: maxCredit}
				if mode == "entries" {
					req = message{typ: tEntriesReq, b: size - 1, keys: true}
				}
				if _, err := writeMsg(st, req); err != nil {
					t.Fatal(err)
				}
				sts = append(sts, st)
				if held := a.srv.Stats().AnswerBytes; held > limit {
					t.Fatalf("answers hold %d bytes, limit %d", held, limit)
				}
			}
			waitFor(t, "a refusal", func() bool { return a.srv.Stats().RefusedByLimit > 0 })
			time.Sleep(200 * time.Millisecond)
			if s := a.srv.Stats(); s.AnswerBytes > limit || s.AnswerBytes == 0 {
				t.Fatalf("answers hold %d bytes, limit %d", s.AnswerBytes, limit)
			}
			refused := 0
			for _, st := range sts {
				st.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				if m, err := readMsg(st, false); err == nil && m.typ == tError && m.code == codeBusy {
					refused++
				}
			}
			if refused == 0 || uint64(refused) != a.srv.Stats().RefusedByLimit {
				t.Fatalf("%d clients read busy, server counted %d", refused, a.srv.Stats().RefusedByLimit)
			}
			for _, st := range sts {
				end(st)
			}
			waitFor(t, "the memory to be given back", func() bool {
				s := a.srv.Stats()
				return s.AnswerBytes == 0 && s.ActiveStreams == 0
			})
			b := newPeer(t)
			conn, _ := connect(t, b, a, nil)
			r := replica(t, b, conn, a.id.PublicKey(), l.ID())
			if err := Pull(testCtx(t), conn, r); err != nil || r.Len() != size {
				t.Fatalf("Pull after the peers left: %v, %d entries", err, r.Len())
			}
		})
	}
}

// The client of a server that is over a limit gets ErrBusy, as it does for MaxStreams.
func TestServerLimitIsErrBusy(t *testing.T) {
	checkGoroutines(t)
	a, l := limited(t, &ServerOptions{MaxTotalStreams: 1}, []int{100})
	if st, m := dial(t, a, l); m.typ != tHead {
		t.Fatalf("answer %+v", m)
	} else {
		defer end(st)
	}
	b := newPeer(t)
	conn, _ := connect(t, b, a, nil)
	r, err := b.st.OpenReplica(a.id.PublicKey(), l.ID(), l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err := Pull(testCtx(t), conn, r); !errors.Is(err, ErrBusy) {
		t.Fatalf("Pull = %v, want ErrBusy", err)
	}
}

// An answer larger than the room reserved before it was built asks for the rest afterwards, and is refused, and its
// entries wiped, if the rest is not there.
func TestServerAnswerBytesGrowsToTheAnswer(t *testing.T) {
	checkGoroutines(t)
	const limit = 2 * MaxMessageSize
	a, l := limited(t, &ServerOptions{MaxAnswerBytes: limit}, []int{3 << 20, 3 << 20})
	req := message{typ: tEntriesReq, a: 0, b: 0, keys: true}
	first, m := dial(t, a, l)
	if m.typ != tHead {
		t.Fatalf("answer %+v", m)
	}
	if _, err := writeMsg(first, req); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first answer to be held", func() bool { return a.srv.Stats().AnswerBytes > 2*3<<20 })
	second, m := dial(t, a, l)
	if m.typ != tHead {
		t.Fatalf("answer %+v", m)
	}
	if _, err := writeMsg(second, req); err != nil {
		t.Fatal(err)
	}
	second.SetReadDeadline(time.Now().Add(timeout))
	if m, err := readMsg(second, false); err != nil || m.typ != tError || m.code != codeBusy {
		t.Fatalf("second answer %+v, %v, want ERROR busy", m, err)
	}
	if s := a.srv.Stats(); s.AnswerBytes > limit || s.AnswerBytes < 2*3<<20 || s.RefusedByLimit != 1 {
		t.Fatalf("stats %+v", s)
	}
}

// The measurements behind the follower and watch defaults, run with KOLO_SYNC_MEASURE=1 -v and no -race; docs/limits.md has them.

type fixture struct {
	owners []*peer
	addrs  []string
	logs   [][]*kolostore.Log
	ctx    context.Context
}

// newFixture starts owners that each offer perOwner logs of entries entries of size bytes, on a listener of their own.
func newFixture(t *testing.T, owners, perOwner, entries, size int) *fixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fx := &fixture{ctx: ctx}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	for range owners {
		a := watchPeer(t, ServerOptions{WatchGap: 10 * time.Millisecond}, nil)
		ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", a.id, nil)
		if err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			defer ln.Close()
			for {
				c, err := ln.Accept(ctx)
				if err != nil {
					return
				}
				wg.Go(func() { a.srv.Serve(ctx, c) })
			}
		})
		var logs []*kolostore.Log
		for range perOwner {
			logs = append(logs, ownSized(t, a, entries, size, func(l *kolostore.Log) Source { return l }))
		}
		fx.owners, fx.addrs, fx.logs = append(fx.owners, a), append(fx.addrs, ln.Addr().String()), append(fx.logs, logs)
	}
	return fx
}

// dial connects c to owner i, through a link with the one-way delay if it is not 0.
func (fx *fixture) dial(t *testing.T, i int, c *peer, delay time.Duration) Conn {
	t.Helper()
	addr := fx.addrs[i]
	if delay > 0 {
		p := netsim.Profile{Delay: delay, Seed: 1}
		down := p
		down.Seed = 2
		link, err := netsim.New(addr, p, down)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { link.Close() })
		addr = link.Addr()
	}
	conn, err := kolosecure.Dial(fx.ctx, addr, c.id, pub(fx.owners[i]), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close()
		time.Sleep(10 * delay) // the close must pass the link before the listener's MaxConnsPerIP counts the connection as gone
	})
	return conn
}

func heapInUse() uint64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// syncAll syncs every log of fx to a fresh follower with opts and prints the time, the pulls at once and the heap used.
func (fx *fixture) syncAll(t *testing.T, delay time.Duration, opts FollowOptions) {
	t.Helper()
	c := newPeer(t)
	f := newFollowerT(t, &opts)
	var tl tally
	tl.watch(f)
	var reps []*kolostore.Replica
	var conns []Conn
	for i, a := range fx.owners {
		conns = append(conns, fx.dial(t, i, c, delay))
		for _, l := range fx.logs[i] {
			rep, err := c.st.OpenReplica(pub(a), l.ID(), l.Header().Encode())
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Add(rep); err != nil {
				t.Fatal(err)
			}
			reps = append(reps, rep)
		}
	}
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	base := heapInUse()
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	})
	start := time.Now()
	for _, conn := range conns {
		follow(t, f, conn)
	}
	for i, rep := range reps {
		want := fx.logs[0][0].Len()
		for deadline := time.Now().Add(5 * time.Minute); rep.Len() != want; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("replica %d has %d of %d entries", i, rep.Len(), want)
			}
		}
	}
	elapsed := time.Since(start)
	close(stop)
	wg.Wait()
	t.Logf("MEASURE logs=%d delay=%v MaxPulls=%d MaxPullsPerConn=%d elapsed=%v pulls=%d perconn=%d held=%dKiB heap=%dMiB",
		len(reps), delay, f.opts.MaxPulls, f.opts.MaxPullsPerConn, elapsed.Round(time.Millisecond), tl.maxRunning, tl.maxOnConn, tl.held>>10, (max(peak.Load(), base)-base)>>20)
}

func TestMeasurePulls(t *testing.T) {
	if os.Getenv("KOLO_SYNC_MEASURE") == "" {
		t.Skip("set KOLO_SYNC_MEASURE=1 to measure")
	}
	many := newFixture(t, 8, 32, 100, 1<<10)
	for _, delay := range []time.Duration{0, 20 * time.Millisecond} {
		for _, n := range []int{1, 2, 4, 8, 16, 32, 64} {
			for run := range 3 {
				t.Run(fmt.Sprintf("MaxPulls=%d/delay=%v/run=%d", n, delay, run), func(t *testing.T) {
					many.syncAll(t, delay, FollowOptions{MaxPulls: n})
				})
			}
		}
	}
	one := newFixture(t, 1, 64, 100, 1<<10)
	for _, delay := range []time.Duration{0, 20 * time.Millisecond} {
		for _, n := range []int{1, 2, 4, 8, 15} {
			for run := range 3 {
				t.Run(fmt.Sprintf("MaxPullsPerConn=%d/delay=%v/run=%d", n, delay, run), func(t *testing.T) {
					one.syncAll(t, delay, FollowOptions{MaxPulls: 64, MaxPullsPerConn: n})
				})
			}
		}
	}
}

// cpuSeconds is the processor time the program has used; the runtime updates it at the end of a collection.
func cpuSeconds() float64 {
	runtime.GC()
	s := []metrics.Sample{{Name: "/cpu/classes/user:cpu-seconds"}}
	metrics.Read(s)
	return s[0].Value.Float64()
}

// TestMeasureWatch prints the heap, first answer, idle processor and push time of n watched logs, then the heap of followed logs.
func TestMeasureWatch(t *testing.T) {
	if os.Getenv("KOLO_SYNC_MEASURE") == "" {
		t.Skip("set KOLO_SYNC_MEASURE=1 to measure")
	}
	for _, n := range []int{55, 256, 1024, 4096} {
		a := newPeer(t)
		var logs []*kolostore.Log
		for range n {
			l, err := a.st.Create(a.id)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.Close() })
			appendN(t, l, 1)
			logs = append(logs, l)
		}
		for _, gap := range []time.Duration{10 * time.Millisecond, 100 * time.Millisecond, time.Second} {
			t.Run(fmt.Sprintf("n=%d/gap=%v", n, gap), func(t *testing.T) {
				srv, err := NewServerWith(allowAll, &ServerOptions{MaxWatched: max(n, maxWatchItems), WatchGap: gap})
				if err != nil {
					t.Fatal(err)
				}
				a.srv = srv
				for _, l := range logs {
					if err := srv.Offer(l); err != nil {
						t.Fatal(err)
					}
				}
				before := heapInUse()
				c := newWatchClient(t, a)
				start := time.Now()
				for i := 0; i < n; i += maxWatchItems {
					var items []watchItem
					for _, l := range logs[i:min(i+maxWatchItems, n)] {
						items = append(items, named(a, l.ID(), 0))
					}
					c.send(items...)
				}
				for got := 0; got < n; {
					got += len(c.heads())
				}
				first := time.Since(start)
				perLog := (int64(heapInUse()) - int64(before)) / int64(n)
				time.Sleep(gap)
				cpu, at := cpuSeconds(), time.Now()
				time.Sleep(3 * time.Second)
				idle := (cpuSeconds() - cpu) / time.Since(at).Seconds()
				var lat []time.Duration
				for i := range 10 {
					time.Sleep(gap / 3)
					sent := time.Now()
					appendN(t, logs[i], 1)
					for pushed := false; !pushed; {
						for _, h := range c.heads() {
							pushed = pushed || h.LogID == logs[i].ID()
						}
					}
					lat = append(lat, time.Since(sent))
				}
				slices.Sort(lat)
				t.Logf("MEASURE watched=%d WatchGap=%v heap/log=%dB first=%v idle-cpu=%.2f%% push-median=%v push-max=%v",
					n, gap, perLog, first.Round(time.Millisecond), idle*100, lat[len(lat)/2].Round(time.Millisecond), lat[len(lat)-1].Round(time.Millisecond))
			})
		}
	}
	for _, n := range []int{1024, 16384, 65536} {
		t.Run(fmt.Sprintf("unknown=%d", n), func(t *testing.T) {
			a := watchPeer(t, ServerOptions{MaxWatched: n}, nil)
			c := newWatchClient(t, a)
			before := heapInUse()
			for i := 0; i < n; i += maxWatchItems {
				var items []watchItem
				for range min(maxWatchItems, n-i) {
					var id kololog.LogID
					rand.Read(id[:])
					items = append(items, named(a, id, 0))
				}
				c.send(items...)
			}
			time.Sleep(5 * testGap)
			t.Logf("MEASURE named-but-not-offered=%d heap/name=%dB", n, (int64(heapInUse())-int64(before))/int64(n))
		})
	}
	for _, n := range []int{256, 1024, 4096} {
		t.Run(fmt.Sprintf("followed=%d", n), func(t *testing.T) {
			a, c := watchPeer(t, ServerOptions{MaxWatched: n}, nil), newPeer(t)
			conn, _ := connect(t, c, a, nil)
			var reps []*kolostore.Replica
			for range n {
				l := ownLog(t, a, 1)
				rep := replica(t, c, conn, pub(a), l.ID())
				if err := Pull(testCtx(t), conn, rep); err != nil {
					t.Fatal(err)
				}
				reps = append(reps, rep)
			}
			before := heapInUse()
			f := newFollowerT(t, nil)
			for _, rep := range reps {
				if err := f.Add(rep); err != nil {
					t.Fatal(err)
				}
			}
			follow(t, f, conn)
			waitFor(t, "every head", func() bool {
				st, err := f.Status(reps[n-1].Header().LogKey, reps[n-1].ID())
				return err == nil && st.Peers == 1
			})
			time.Sleep(200 * time.Millisecond)
			t.Logf("MEASURE followed=%d heap/log=%dB", n, (int64(heapInUse())-int64(before))/int64(n))
		})
	}
}
