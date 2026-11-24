package kolosync

import (
	"context"
	"slices"
	"sync"
	"time"

	kolostore "github.com/ciranda-dev/kolo-store"
)

// fakeClock is a clock that tests move by hand.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at   time.Time
	fn   func()
	live bool
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1<<30, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) after(d time.Duration, fn func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	tm := &fakeTimer{at: c.t.Add(d), fn: fn, live: true}
	c.timers = append(c.timers, tm)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := tm.live
		tm.live = false
		return was
	}
}

// pending returns the time left on each timer that has neither fired nor been stopped.
func (c *fakeClock) pending() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []time.Duration
	for _, tm := range c.timers {
		if tm.live {
			out = append(out, tm.at.Sub(c.t))
		}
	}
	return out
}

// advance moves the clock on by d and runs the timers that fall due, earliest first.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	var due []*fakeTimer
	for _, tm := range c.timers {
		if tm.live && !tm.at.After(c.t) {
			tm.live = false
			due = append(due, tm)
		}
	}
	c.mu.Unlock()
	slices.SortFunc(due, func(a, b *fakeTimer) int { return a.at.Compare(b.at) })
	for _, tm := range due {
		tm.fn()
	}
}

func (f *Follower) useClock(c *fakeClock) { f.clk = clock{now: c.now, after: c.after} }

func (f *Follower) usePull(fn func(ctx context.Context, conn Conn, rep *kolostore.Replica, keysFrom uint64) (uint64, error)) {
	f.pull = fn
}
