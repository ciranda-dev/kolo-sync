package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"slices"
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

func pub(p *peer) ed25519.PublicKey { return p.id.PublicKey() }

func newFollowerT(t *testing.T, opts *FollowOptions) *Follower {
	t.Helper()
	f, err := NewFollower(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// run is a Follow that ends with the test.
type run struct {
	done chan struct{}
	err  error
}

func follow(t *testing.T, f *Follower, conn Conn) *run {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{done: make(chan struct{})}
	go func() {
		r.err = f.Follow(ctx, conn)
		close(r.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-r.done
	})
	return r
}

func waitLen(t *testing.T, rep *kolostore.Replica, n uint64) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d entries", n), func() bool { return rep.Len() == n })
}

func waitEvent(t *testing.T, f *Follower, kind FollowEventKind) FollowEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		ev, err := f.Next(ctx)
		if err != nil {
			t.Fatalf("waiting for event %d: %v", kind, err)
		}
		if ev.Kind == kind {
			return ev
		}
	}
}

// quiet checks that cond stays false for d.
func quiet(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			t.Fatalf("%s", what)
		}
	}
}

// follow1 is one owner with a log of n entries, a follower peer connected to it and a replica of the log.
type follow1 struct {
	a, c *peer
	l    *kolostore.Log
	conn *kolosecure.Conn
	rep  *kolostore.Replica
}

func newFollow1(t *testing.T, n int) follow1 {
	t.Helper()
	a, c := watchPeer(t, ServerOptions{}, nil), newPeer(t)
	l := ownLog(t, a, n)
	conn, _ := connect(t, c, a, nil)
	return follow1{a, c, l, conn, replica(t, c, conn, pub(a), l.ID())}
}

func TestNewFollower(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts *FollowOptions
		ok   bool
	}{
		{"nil", nil, true},
		{"zero", &FollowOptions{}, true},
		{"set", &FollowOptions{MaxPulls: 1, MaxPullsPerConn: MaxStreams - 1, RetryMin: 100 * time.Millisecond, RetryMax: time.Hour, Poll: time.Second}, true},
		{"negative pulls", &FollowOptions{MaxPulls: -1}, false},
		{"pulls per connection past the streams", &FollowOptions{MaxPullsPerConn: MaxStreams}, false},
		{"retry floor too low", &FollowOptions{RetryMin: time.Millisecond}, false},
		{"retry floor of two minutes", &FollowOptions{RetryMin: 2 * time.Minute}, true},
		{"ceiling below the floor", &FollowOptions{RetryMin: 10 * time.Second, RetryMax: time.Second}, false},
		{"ceiling of two hours", &FollowOptions{RetryMax: 2 * time.Hour}, true},
		{"poll below the floor", &FollowOptions{Poll: 10 * time.Millisecond}, false},
		{"poll above the retry ceiling", &FollowOptions{Poll: 11 * time.Minute}, true},
		{"negative poll", &FollowOptions{Poll: -time.Second}, false},
	} {
		f, err := NewFollower(tc.opts)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrInvalidArgument)) {
			t.Errorf("%s: %v, want ok %v", tc.name, err, tc.ok)
		}
		if f != nil {
			f.Close()
		}
	}
}

func TestFollowAdd(t *testing.T) {
	checkGoroutines(t)
	x := newFollow1(t, 2)
	f := newFollowerT(t, nil)
	if err := f.Add(nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Add(nil) = %v", err)
	}
	if err := f.Add(x.rep); err != nil {
		t.Fatal(err)
	}
	if err := f.Add(x.rep); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("second Add = %v, want ErrInvalidArgument", err)
	}
	l2 := ownLog(t, x.a, 1)
	if _, err := f.Status(pub(x.a), l2.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status of a log not followed = %v", err)
	}
}

// The number of followed logs has no bound: the application chooses its replicas, not a peer.
func TestFollowAddHasNoCount(t *testing.T) {
	checkGoroutines(t)
	a, c := newPeer(t), newPeer(t)
	f := newFollowerT(t, nil)
	for range DefaultMaxWatched + 1 {
		l, err := a.st.Create(a.id)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		rep, err := c.st.OpenReplica(pub(a), l.ID(), l.Header().Encode())
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Add(rep); err != nil {
			t.Fatalf("Add of log %d: %v", len(f.logs)+1, err)
		}
	}
}

func TestFollowInitialSync(t *testing.T) {
	checkGoroutines(t)
	a, b, c := watchPeer(t, ServerOptions{}, nil), watchPeer(t, ServerOptions{}, nil), newPeer(t)
	ca, _ := connect(t, c, a, nil)
	cb, _ := connect(t, c, b, nil)
	type pair struct {
		l   *kolostore.Log
		rep *kolostore.Replica
	}
	var pairs []pair
	for _, tc := range []struct {
		own  *peer
		conn *kolosecure.Conn
		n    int
	}{{a, ca, 3}, {a, ca, 5}, {b, cb, 4}} {
		l := ownLog(t, tc.own, tc.n)
		pairs = append(pairs, pair{l, replica(t, c, tc.conn, pub(tc.own), l.ID())})
	}
	f := newFollowerT(t, nil)
	for _, p := range pairs {
		if err := f.Add(p.rep); err != nil {
			t.Fatal(err)
		}
	}
	follow(t, f, ca)
	follow(t, f, cb)
	grew := map[kololog.LogID]uint64{}
	for len(grew) < len(pairs) {
		ev := waitEvent(t, f, FollowGrew)
		grew[ev.LogID] = ev.Len
	}
	for _, p := range pairs {
		waitLen(t, p.rep, p.l.Len())
		sameEntries(t, p.rep, p.l)
		st, err := f.Status(p.rep.Header().LogKey, p.l.ID())
		if err != nil || st.Len != p.l.Len() || st.Largest != p.l.Len() || st.Peers != 1 || st.LastGrown.IsZero() {
			t.Fatalf("Status = %+v, %v", st, err)
		}
	}
}

// Each append reaches the follower through WATCH, which no poll replaces (Poll is 0).
func TestFollowContinuous(t *testing.T) {
	checkGoroutines(t)
	x := newFollow1(t, 2)
	f := newFollowerT(t, nil)
	if err := f.Add(x.rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, x.conn)
	waitLen(t, x.rep, 2)
	for i := range 10 {
		start := time.Now()
		appendN(t, x.l, 1)
		waitLen(t, x.rep, uint64(3+i))
		if d := time.Since(start); d > time.Second {
			t.Fatalf("append %d took %v to arrive", i, d)
		}
	}
	sameEntries(t, x.rep, x.l)
}

// A pull that fails waits RetryMin plus a draw below the ceiling that doubles up to RetryMax.
func TestFollowBackoffJitter(t *testing.T) {
	checkGoroutines(t)
	x := newFollow1(t, 3)
	const lo, hi = 100 * time.Millisecond, 10 * time.Second
	f := newFollowerT(t, &FollowOptions{RetryMin: lo, RetryMax: hi})
	clk := newFakeClock()
	f.useClock(clk)
	var calls atomic.Int32
	f.usePull(func(context.Context, Conn, *kolostore.Replica, uint64) (uint64, error) {
		calls.Add(1)
		return 0, ErrBusy
	})
	if err := f.Add(x.rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, x.conn)
	seen := map[time.Duration]bool{}
	var longest time.Duration
	for i := range 200 {
		waitFor(t, "the next retry to be timed", func() bool { return calls.Load() == int32(i+1) && len(clk.pending()) == 1 })
		d := clk.pending()[0]
		ceil := min(hi, lo<<(i+1))
		if i+1 > 20 {
			ceil = hi
		}
		if d < lo || d >= ceil {
			t.Fatalf("failure %d: retry in %v, want [%v, %v)", i+1, d, lo, ceil)
		}
		seen[d] = true
		longest = max(longest, d)
		clk.advance(d)
	}
	if len(seen) < 100 {
		t.Fatalf("only %d distinct delays in 200 draws", len(seen))
	}
	if longest < hi/2 {
		t.Fatalf("the longest delay was %v, want it to reach toward %v", longest, hi)
	}
}

// Two peers that offer the same head start one pull between them.
func TestFollowOnePullPerReplica(t *testing.T) {
	checkGoroutines(t)
	a, b, c := watchPeer(t, ServerOptions{}, nil), watchPeer(t, ServerOptions{}, nil), newPeer(t)
	l := ownLog(t, a, 5)
	ba, _ := connect(t, b, a, nil)
	rb := replica(t, b, ba, pub(a), l.ID())
	if err := Pull(testCtx(t), ba, rb); err != nil {
		t.Fatal(err)
	}
	if err := b.srv.Offer(rb); err != nil {
		t.Fatal(err)
	}
	ca, _ := connect(t, c, a, nil)
	cb, _ := connect(t, c, b, nil)
	rc := replica(t, c, ca, pub(a), l.ID())
	f := newFollowerT(t, nil)
	var started, running, most atomic.Int32
	release := make(chan struct{})
	real := f.pullWith
	f.usePull(func(ctx context.Context, conn Conn, rep *kolostore.Replica, k uint64) (uint64, error) {
		started.Add(1)
		n := running.Add(1)
		defer running.Add(-1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		select {
		case <-release:
		case <-ctx.Done():
			return k, ctx.Err()
		}
		return real(ctx, conn, rep, k)
	})
	if err := f.Add(rc); err != nil {
		t.Fatal(err)
	}
	follow(t, f, ca)
	follow(t, f, cb)
	waitFor(t, "both peers to offer the head", func() bool {
		st, _ := f.Status(pub(a), l.ID())
		return st.Peers == 2
	})
	close(release)
	waitLen(t, rc, 5)
	quiet(t, "a second pull started", 10*testGap, func() bool { return started.Load() > 1 })
	if most.Load() != 1 {
		t.Fatalf("%d pulls of one replica at once", most.Load())
	}
}

func TestFollowErrorClasses(t *testing.T) {
	const lo = 100 * time.Millisecond
	local := func(rep *kolostore.Replica) error {
		pulling.Store(rep, struct{}{})
		t.Cleanup(func() { pulling.Delete(rep) })
		return ErrBusy
	}
	for _, tc := range []struct {
		name string
		err  func(*kolostore.Replica) error
		want string // retry, once, held, diverged or local
	}{
		{"busy", func(*kolostore.Replica) error { return ErrBusy }, "retry"},
		{"timeout", func(*kolostore.Replica) error { return fmt.Errorf("%w: slow", ErrTimeout) }, "retry"},
		{"connection", func(*kolostore.Replica) error { return errors.New("kolosync: connection lost") }, "retry"},
		{"not found", func(*kolostore.Replica) error { return ErrNotFound }, "once"},
		{"invalid", func(*kolostore.Replica) error { return ErrInvalid }, "held"},
		{"protocol", func(*kolostore.Replica) error { return fmt.Errorf("%w: odd", ErrProtocol) }, "held"},
		{"too large", func(*kolostore.Replica) error { return ErrTooLarge }, "held"},
		{"diverged", func(*kolostore.Replica) error { return ErrDiverged }, "diverged"},
		{"another Pull of the replica", local, "local"},
		{"replica closed", func(*kolostore.Replica) error { return fmt.Errorf("kolosync: %w", kolostore.ErrClosed) }, "local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			x := newFollow1(t, 3)
			f := newFollowerT(t, &FollowOptions{RetryMin: lo, RetryMax: time.Second})
			clk := newFakeClock()
			f.useClock(clk)
			var calls atomic.Int32
			f.usePull(func(_ context.Context, _ Conn, rep *kolostore.Replica, k uint64) (uint64, error) {
				calls.Add(1)
				return k, tc.err(rep)
			})
			if err := f.Add(x.rep); err != nil {
				t.Fatal(err)
			}
			follow(t, f, x.conn)
			if tc.want == "diverged" {
				if ev := waitEvent(t, f, FollowDiverged); !errors.Is(ev.Err, ErrDiverged) || !bytes.Equal(ev.Peer, pub(x.a)) {
					t.Fatalf("event %+v", ev)
				}
			} else if ev := waitEvent(t, f, FollowPullFailed); ev.Err == nil || !bytes.Equal(ev.Peer, pub(x.a)) || ev.Len != 0 {
				t.Fatalf("event %+v", ev)
			}
			waitFor(t, "the first pull", func() bool { return calls.Load() == 1 })
			timers := clk.pending()
			switch tc.want {
			case "retry":
				if len(timers) != 1 || timers[0] < lo || timers[0] >= 2*lo {
					t.Fatalf("timers %v, want one in [%v, %v)", timers, lo, 2*lo)
				}
				clk.advance(timers[0])
				waitFor(t, "the retry", func() bool { return calls.Load() == 2 })
			case "local":
				if len(timers) != 1 || timers[0] != lo {
					t.Fatalf("timers %v, want one of %v and no jitter", timers, lo)
				}
			default:
				if len(timers) != 0 {
					t.Fatalf("timers %v, want none", timers)
				}
				clk.advance(time.Hour)
				appendN(t, x.l, 1)
				if tc.want == "once" {
					waitFor(t, "a new head to be pulled", func() bool { return calls.Load() == 2 })
				} else {
					waitFor(t, "the new head to be seen", func() bool {
						st, _ := f.Status(pub(x.a), x.l.ID())
						return st.Largest == 4
					})
					quiet(t, "pulled again", 10*testGap, func() bool { return calls.Load() != 1 })
				}
			}
		})
	}
}

// legacyCount counts the WATCH_REQs refused and the streams proxied.
type legacyCount struct{ refused, served atomic.Int32 }

// legacy returns c's end of a connection to a, whose server answers WATCH_REQ with ERROR 4 as v0.1.0 does.
func legacy(t *testing.T, c, a *peer) (*kolosecure.Conn, *legacyCount) {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cc, front := connect(t, c, &peer{id: id}, nil)
	up, _ := connect(t, &peer{id: id2}, a, nil)
	ctx, cancel := context.WithCancel(context.Background())
	n := new(legacyCount)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			st, err := front.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer end(st)
				m, err := readMsg(st, true)
				if err != nil {
					return
				}
				if m.typ == tWatchReq {
					n.refused.Add(1)
					_, _ = writeMsg(st, message{typ: tError, code: codeProtocol})
					return
				}
				us, err := up.OpenStream(ctx)
				if err != nil {
					return
				}
				defer end(us)
				if _, err := writeMsg(us, m); err != nil {
					return
				}
				go func() {
					_, _ = io.Copy(us, st)
					_ = us.Close()
				}()
				_, _ = io.Copy(st, us)
				n.served.Add(1)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return cc, n
}

func TestFollowFallsBackToPoll(t *testing.T) {
	for _, tc := range []struct {
		name string
		poll time.Duration
	}{{"no poll", 0}, {"poll", 100 * time.Millisecond}} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, c := watchPeer(t, ServerOptions{}, nil), newPeer(t)
			l := ownLog(t, a, 5)
			conn, n := legacy(t, c, a)
			rep := replica(t, c, conn, pub(a), l.ID())
			f := newFollowerT(t, &FollowOptions{RetryMin: 100 * time.Millisecond, Poll: tc.poll})
			if err := f.Add(rep); err != nil {
				t.Fatal(err)
			}
			follow(t, f, conn)
			waitLen(t, rep, 5)
			appendN(t, l, 2)
			if tc.poll == 0 {
				quiet(t, "an append arrived with no poll and no WATCH", 20*testGap, func() bool { return rep.Len() != 5 })
			} else {
				waitLen(t, rep, 7)
			}
			if got := n.refused.Load(); got != 1 {
				t.Fatalf("%d WATCH_REQs sent, want 1", got)
			}
		})
	}
}

func TestFollowCiphertext(t *testing.T) {
	for _, ciphertext := range []bool{false, true} {
		t.Run(fmt.Sprint("ciphertext ", ciphertext), func(t *testing.T) {
			checkGoroutines(t)
			x := newFollow1(t, 4)
			f := newFollowerT(t, &FollowOptions{Ciphertext: ciphertext})
			if err := f.Add(x.rep); err != nil {
				t.Fatal(err)
			}
			follow(t, f, x.conn)
			waitLen(t, x.rep, 4)
			for i := range uint64(4) {
				var info kololog.EntryInfo
				waitFor(t, "the entry's state", func() bool {
					var err error
					info, err = x.rep.EntryInfo(i)
					return err == nil && (ciphertext || info.Keyed)
				})
				if info.Keyed == ciphertext {
					t.Fatalf("entry %d: key held %v with Ciphertext %v", i, info.Keyed, ciphertext)
				}
			}
			if ciphertext {
				quiet(t, "a key arrived", 10*testGap, func() bool { info, _ := x.rep.EntryInfo(0); return info.Keyed })
			}
		})
	}
}

func TestFollowRemove(t *testing.T) {
	checkGoroutines(t)
	x := newFollow1(t, 2)
	f := newFollowerT(t, nil)
	if err := f.Add(x.rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, x.conn)
	waitLen(t, x.rep, 2)
	f.Remove(pub(x.a), x.l.ID())
	if _, err := f.Status(pub(x.a), x.l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after Remove = %v", err)
	}
	appendN(t, x.l, 1)
	quiet(t, "a removed log grew", 10*testGap, func() bool { return x.rep.Len() != 2 })
	if err := f.Add(x.rep); err != nil {
		t.Fatalf("Add after Remove: %v", err)
	}
	waitLen(t, x.rep, 3)
}

// Remove ends a pull of the log and returns after it did.
func TestFollowRemoveEndsPull(t *testing.T) {
	checkGoroutines(t)
	x := newFollow1(t, 2)
	f := newFollowerT(t, nil)
	var entered, ended atomic.Bool
	f.usePull(func(ctx context.Context, _ Conn, _ *kolostore.Replica, k uint64) (uint64, error) {
		entered.Store(true)
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		ended.Store(true)
		return k, ctx.Err()
	})
	if err := f.Add(x.rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, x.conn)
	waitFor(t, "the pull to start", entered.Load)
	f.Remove(pub(x.a), x.l.ID())
	if !ended.Load() {
		t.Fatal("Remove returned before the pull ended")
	}
	quiet(t, "an event for a removed log", 5*testGap, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		_, err := f.Next(ctx)
		return err == nil
	})
}

func TestFollowRefusesBadConn(t *testing.T) {
	checkGoroutines(t)
	x := newFollow1(t, 1)
	f := newFollowerT(t, nil)
	for name, conn := range map[string]Conn{
		"nil":       nil,
		"typed nil": (*kolosecure.Conn)(nil),
		"short key": &shortKey{Conn: x.conn},
	} {
		if err := f.Follow(testCtx(t), conn); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: Follow = %v, want ErrInvalidArgument", name, err)
		}
	}
	r := follow(t, f, x.conn)
	waitFor(t, "the first Follow to register", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.links) == 1
	})
	if err := f.Follow(testCtx(t), x.conn); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Follow of the connection = %v, want ErrBusy", err)
	}
	select {
	case <-r.done:
		t.Fatalf("the first Follow ended: %v", r.err)
	default:
	}
}

type shortKey struct{ Conn }

func (*shortKey) RemotePublicKey() ed25519.PublicKey { return ed25519.PublicKey{1, 2, 3} }

func TestFollowCloseEndsEverything(t *testing.T) {
	checkGoroutines(t)
	a, b, c := watchPeer(t, ServerOptions{}, nil), watchPeer(t, ServerOptions{}, nil), newPeer(t)
	ca, _ := connect(t, c, a, nil)
	cb, _ := connect(t, c, b, nil)
	la, lb := ownLog(t, a, 2), ownLog(t, b, 2)
	f, err := NewFollower(nil)
	if err != nil {
		t.Fatal(err)
	}
	var pulls, stopped atomic.Int32
	f.usePull(func(ctx context.Context, _ Conn, _ *kolostore.Replica, k uint64) (uint64, error) {
		pulls.Add(1)
		<-ctx.Done()
		stopped.Add(1)
		return k, ctx.Err()
	})
	repA := replica(t, c, ca, pub(a), la.ID())
	for _, rep := range []*kolostore.Replica{repA, replica(t, c, cb, pub(b), lb.ID())} {
		if err := f.Add(rep); err != nil {
			t.Fatal(err)
		}
	}
	ra, rb := follow(t, f, ca), follow(t, f, cb)
	next := make(chan error, 1)
	go func() {
		_, err := f.Next(context.Background())
		next <- err
	}()
	waitFor(t, "both pulls to start", func() bool { return pulls.Load() == 2 })
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if stopped.Load() != 2 {
		t.Fatalf("%d pulls ended when Close returned, want 2", stopped.Load())
	}
	for _, r := range []*run{ra, rb} {
		<-r.done
		if !errors.Is(r.err, ErrClosed) {
			t.Fatalf("Follow = %v, want ErrClosed", r.err)
		}
	}
	if err := <-next; !errors.Is(err, ErrClosed) {
		t.Fatalf("Next = %v, want ErrClosed", err)
	}
	if err := f.Add(repA); !errors.Is(err, ErrClosed) {
		t.Fatalf("Add = %v, want ErrClosed", err)
	}
	if err := f.Follow(testCtx(t), ca); !errors.Is(err, ErrClosed) {
		t.Fatalf("Follow = %v, want ErrClosed", err)
	}
	if err := f.Hint(kololog.Head{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Hint = %v, want ErrClosed", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

// serveStreams answers the nth stream opened on conn with fn, until the test ends.
func serveStreams(t *testing.T, conn *kolosecure.Conn, fn func(n int, st *kolotransport.Stream)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := 1; ; n++ {
			st, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer end(st)
				fn(n, st)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// scripted is a follower of a's log connected to a peer that only runs script, whose pulls are counted and do nothing.
type scripted struct {
	a, c  *peer
	l     *kolostore.Log
	rep   *kolostore.Replica
	f     *Follower
	pulls atomic.Int32
}

func newScripted(t *testing.T, n int, opts *FollowOptions, script func(n int, st *kolotransport.Stream)) *scripted {
	t.Helper()
	a, c := watchPeer(t, ServerOptions{}, nil), newPeer(t)
	l := ownLog(t, a, n)
	ca, _ := connect(t, c, a, nil)
	s := &scripted{a: a, c: c, l: l, rep: replica(t, c, ca, pub(a), l.ID()), f: newFollowerT(t, opts)}
	s.f.usePull(func(_ context.Context, _ Conn, _ *kolostore.Replica, k uint64) (uint64, error) {
		s.pulls.Add(1)
		return k, ErrBusy
	})
	x := &peer{id: a.id}
	cx, xc := connect(t, c, x, nil)
	serveStreams(t, xc, script)
	if err := s.f.Add(s.rep); err != nil {
		t.Fatal(err)
	}
	follow(t, s.f, cx)
	return s
}

// watchScript answers the first stream's WATCH_REQ with heads and closes ended when the follower ends it.
func watchScript(t *testing.T, heads func() [][]byte, ended chan struct{}) func(int, *kolotransport.Stream) {
	return func(n int, st *kolotransport.Stream) {
		if n > 1 {
			return
		}
		if m, err := readMsg(st, true); err != nil || m.typ != tWatchReq {
			return
		}
		if _, err := writeMsg(st, message{typ: tWatch, heads: heads()}); err != nil {
			return
		}
		for {
			if _, err := readMsg(st, true); err != nil {
				close(ended)
				return
			}
		}
	}
}

func signedHead(t *testing.T, l interface{ Head() (kololog.Head, error) }) kololog.Head {
	t.Helper()
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A head that names a log not asked for, does not decode or does not verify ends the watch and counts for nothing.
func TestWatchForgedHeadIgnored(t *testing.T) {
	other := newPeer(t)
	lo := ownLog(t, other, 2)
	for _, tc := range []struct {
		name  string
		heads func(l, l2 *kolostore.Log) []byte
	}{
		{"other key", func(*kolostore.Log, *kolostore.Log) []byte { return signedHead(t, lo).Encode() }},
		{"other log ID", func(_, l2 *kolostore.Log) []byte { return signedHead(t, l2).Encode() }},
		{"bad signature", func(l, _ *kolostore.Log) []byte {
			h := signedHead(t, l)
			h.Signature = slices.Clone(h.Signature)
			h.Signature[0] ^= 1
			return h.Encode()
		}},
		{"garbage", func(*kolostore.Log, *kolostore.Log) []byte { return bytes.Repeat([]byte{7}, 200) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			var s *scripted
			ready, ended := make(chan struct{}), make(chan struct{})
			var l2 *kolostore.Log
			script := watchScript(t, func() [][]byte {
				<-ready
				return [][]byte{tc.heads(s.l, l2)}
			}, ended)
			s = newScripted(t, 5, nil, script)
			l2 = ownLog(t, s.a, 3)
			close(ready)
			select {
			case <-ended:
			case <-time.After(10 * time.Second):
				t.Fatal("the follower kept the watch stream")
			}
			st, err := s.f.Status(pub(s.a), s.l.ID())
			if err != nil || st.Peers != 0 || st.Largest != 0 || s.pulls.Load() != 0 {
				t.Fatalf("status %+v, %v, %d pulls: a forged head counted", st, err, s.pulls.Load())
			}
		})
	}
	t.Run("genuine head", func(t *testing.T) {
		checkGoroutines(t)
		var s *scripted
		ready := make(chan struct{})
		script := watchScript(t, func() [][]byte {
			<-ready
			return [][]byte{signedHead(t, s.l).Encode()}
		}, make(chan struct{}))
		s = newScripted(t, 5, nil, script)
		close(ready)
		waitFor(t, "a pull", func() bool { return s.pulls.Load() > 0 })
		if st, _ := s.f.Status(pub(s.a), s.l.ID()); st.Peers != 1 || st.Largest != 5 {
			t.Fatalf("status %+v", st)
		}
	})
}

// A head older than the replica, or equal to it, stores nothing and starts no pull.
func TestWatchOldHeadNoPull(t *testing.T) {
	checkGoroutines(t)
	var s *scripted
	ended := make(chan struct{})
	var h3 kololog.Head
	ready := make(chan struct{})
	script := watchScript(t, func() [][]byte {
		<-ready
		return [][]byte{h3.Encode(), signedHead(t, s.l).Encode()}
	}, ended)
	s = newScripted(t, 3, nil, script)
	h3 = signedHead(t, s.l)
	appendN(t, s.l, 2)
	ca, _ := connect(t, s.c, s.a, nil)
	if err := Pull(testCtx(t), ca, s.rep); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, s.rep)
	close(ready)
	waitFor(t, "the heads to be seen", func() bool {
		st, _ := s.f.Status(pub(s.a), s.l.ID())
		return st.Peers == 1
	})
	quiet(t, "the stream ended or a pull started", 10*testGap, func() bool {
		select {
		case <-ended:
			return true
		default:
		}
		return s.pulls.Load() != 0
	})
	if snapshot(t, s.rep) != before {
		t.Fatal("the replica changed")
	}
	if err := s.f.Hint(h3); err != nil {
		t.Fatalf("Hint of an older head = %v", err)
	}
	if s.pulls.Load() != 0 {
		t.Fatal("a hint of an older head started a pull")
	}
}

// Two histories of the same size: the second one a peer offers is seen at once, not only when it grows.
func TestWatchEqualSizeOtherRootDiverges(t *testing.T) {
	checkGoroutines(t)
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, ra, rb := forks(t, id, 3, 2, 2)
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
	if err := Pull(testCtx(t), ca, rep); err != nil {
		t.Fatal(err)
	}
	f := newFollowerT(t, nil)
	var pulls atomic.Int32
	f.usePull(func(context.Context, Conn, *kolostore.Replica, uint64) (uint64, error) {
		pulls.Add(1)
		return 0, ErrBusy
	})
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	follow(t, f, cb)
	ev := waitEvent(t, f, FollowDiverged)
	if !errors.Is(ev.Err, ErrDiverged) || !bytes.Equal(ev.Peer, pub(pb)) || ev.Len != 5 {
		t.Fatalf("event %+v", ev)
	}
	if err := f.Hint(signedHead(t, rb)); !errors.Is(err, ErrDiverged) {
		t.Fatalf("Hint of the other history = %v, want ErrDiverged", err)
	}
	if pulls.Load() != 0 {
		t.Fatal("a pull started for a head no larger than the replica")
	}
}

// A peer that failed is skipped for the log while it waits, so another that offers less is asked.
func TestSourceSkipsPeerInBackoff(t *testing.T) {
	checkGoroutines(t)
	a, b, c := watchPeer(t, ServerOptions{}, nil), watchPeer(t, ServerOptions{}, nil), newPeer(t)
	l := ownLog(t, a, 8)
	ba, _ := connect(t, b, a, nil)
	rb := replica(t, b, ba, pub(a), l.ID())
	if err := Pull(testCtx(t), ba, rb); err != nil {
		t.Fatal(err)
	}
	if err := b.srv.Offer(rb); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2)
	ca, _ := connect(t, c, a, nil)
	cb, _ := connect(t, c, b, nil)
	rc := replica(t, c, ca, pub(a), l.ID())
	f := newFollowerT(t, &FollowOptions{RetryMin: 100 * time.Millisecond, RetryMax: time.Second})
	f.useClock(newFakeClock())
	var mu sync.Mutex
	var order []string
	gate := make(chan struct{})
	real := f.pullWith
	f.usePull(func(ctx context.Context, conn Conn, rep *kolostore.Replica, k uint64) (uint64, error) {
		fromA := bytes.Equal(conn.RemotePublicKey(), pub(a))
		mu.Lock()
		order = append(order, map[bool]string{true: "a", false: "b"}[fromA])
		mu.Unlock()
		if fromA {
			<-gate
			return k, ErrBusy
		}
		return real(ctx, conn, rep, k)
	})
	if err := f.Add(rc); err != nil {
		t.Fatal(err)
	}
	follow(t, f, ca)
	waitFor(t, "the pull from a", func() bool { mu.Lock(); defer mu.Unlock(); return len(order) == 1 })
	follow(t, f, cb)
	waitFor(t, "both peers to offer", func() bool {
		st, _ := f.Status(pub(a), l.ID())
		return st.Peers == 2
	})
	close(gate)
	waitLen(t, rc, 8)
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(order, []string{"a", "b"}) {
		t.Fatalf("pulls from %v, want a then b", order)
	}
}

func TestHintVerifies(t *testing.T) {
	checkGoroutines(t)
	var deny atomic.Bool
	var asked atomic.Int32
	a, c := watchPeer(t, ServerOptions{}, func(_, _ ed25519.PublicKey, _ kololog.LogID) Access {
		asked.Add(1)
		if deny.Load() {
			return NoAccess
		}
		return Keys
	}), newPeer(t)
	l := ownLog(t, a, 5)
	other := ownLog(t, a, 2)
	conn, _ := legacy(t, c, a)
	rep := replica(t, c, conn, pub(a), l.ID())
	f := newFollowerT(t, nil)
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	if err := f.Hint(signedHead(t, other)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Hint of a log not followed = %v, want ErrNotFound", err)
	}
	forged := signedHead(t, l)
	forged.Signature = slices.Clone(forged.Signature)
	forged.Signature[0] ^= 1
	if err := f.Hint(forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Hint of a forged head = %v, want ErrInvalid", err)
	}
	// The log is refused to the first round of the connection, so only the hint can make a pull.
	deny.Store(true)
	before := asked.Load()
	follow(t, f, conn)
	waitFor(t, "the first round", func() bool { return asked.Load() > before })
	deny.Store(false)
	if err := f.Hint(signedHead(t, l)); err != nil {
		t.Fatal(err)
	}
	waitLen(t, rep, 5)
}

// ERROR 3 on the watch stream reopens it once with the current list; a second one is a peer without WATCH.
func TestFollowTooManyWatched(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []uint64 // the type of the answer to each WATCH_REQ: tError for ERROR 3, tWatch for an empty WATCH
		streams int32    // watch streams opened in the end
		polled  bool
	}{
		{"once", []uint64{tError, tWatch}, 2, false},
		{"twice", []uint64{tError, tError}, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			var watches, heads atomic.Int32
			newScripted(t, 2, nil, func(_ int, st *kolotransport.Stream) {
				m, err := readMsg(st, true)
				if err != nil {
					return
				}
				switch m.typ {
				case tWatchReq:
					i := int(watches.Add(1)) - 1
					if i >= len(tc.answers) {
						return
					}
					if tc.answers[i] == tError {
						_, _ = writeMsg(st, message{typ: tError, code: codeTooLarge})
						return
					}
					_, _ = writeMsg(st, message{typ: tWatch})
					for {
						if _, err := readMsg(st, true); err != nil {
							return
						}
					}
				case tHeadReq:
					heads.Add(1)
					_, _ = writeMsg(st, message{typ: tError, code: codeNotFound})
				}
			})
			if tc.polled {
				waitFor(t, "the first round of polls", func() bool { return heads.Load() > 0 })
			} else {
				waitFor(t, "the second watch stream", func() bool { return watches.Load() == 2 })
			}
			quiet(t, "another stream", 10*testGap, func() bool { return watches.Load() > tc.streams || (!tc.polled && heads.Load() > 0) })
			if watches.Load() != tc.streams {
				t.Fatalf("%d watch streams, want %d", watches.Load(), tc.streams)
			}
		})
	}
}

// Only the newest event per log and kind waits, so the queue stays bounded.
func TestFollowEventsCoalesce(t *testing.T) {
	checkGoroutines(t)
	x := newFollow1(t, 1)
	f := newFollowerT(t, nil)
	if err := f.Add(x.rep); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	fl := f.logs[logName{owner: [32]byte(pub(x.a)), id: x.l.ID()}]
	for i := range 100 {
		f.post(fl, FollowEvent{Kind: FollowGrew, Len: uint64(i)})
		f.post(fl, FollowEvent{Kind: FollowPullFailed, Len: uint64(i)})
	}
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	for _, kind := range []FollowEventKind{FollowGrew, FollowPullFailed} {
		ev, err := f.Next(ctx)
		if err != nil || ev.Kind != kind || ev.Len != 99 || !bytes.Equal(ev.Owner, pub(x.a)) || ev.LogID != x.l.ID() {
			t.Fatalf("Next = %+v, %v, want the newest %d", ev, err, kind)
		}
	}
	if ev, err := f.Next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a third event waits: %+v, %v", ev, err)
	}
}

// Follow returns the error of the connection when it ends, whichever side closed it.
func TestFollowEndsWithConnection(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(fmt.Sprint("local close ", local), func(t *testing.T) {
			checkGoroutines(t)
			a, c := watchPeer(t, ServerOptions{}, nil), newPeer(t)
			l := ownLog(t, a, 2)
			ca, ac := connect(t, c, a, nil)
			rep := replica(t, c, ca, pub(a), l.ID())
			f := newFollowerT(t, &FollowOptions{RetryMin: 100 * time.Millisecond})
			if err := f.Add(rep); err != nil {
				t.Fatal(err)
			}
			r := follow(t, f, ca)
			waitLen(t, rep, 2)
			if local {
				ca.Close()
			} else {
				ac.Close()
			}
			select {
			case <-r.done:
			case <-time.After(10 * time.Second):
				t.Fatal("Follow did not return")
			}
			if r.err == nil || errors.Is(r.err, ErrClosed) || errors.Is(r.err, context.Canceled) {
				t.Fatalf("Follow = %v, want the error of the connection", r.err)
			}
		})
	}
}

func TestFollowEventKindString(t *testing.T) {
	for k, want := range map[FollowEventKind]string{FollowGrew: "grew", FollowPullFailed: "pull failed", FollowDiverged: "diverged", 0: "FollowEventKind(0)"} {
		if got := k.String(); got != want {
			t.Errorf("%d: %q, want %q", int(k), got, want)
		}
	}
}
