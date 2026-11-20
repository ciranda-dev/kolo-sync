package kolosync

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	"github.com/ciranda-dev/kolo-sync/internal/netsim"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestMeterZeroValueAndReuse(t *testing.T) {
	var m PullMeter
	if s := m.Stats(); s != (PullStats{}) {
		t.Fatalf("zero meter: %+v", s)
	}
	m.begin()
	m.requested()
	m.inFlight(2)
	m.answerRead(100, 3)
	time.Sleep(20 * time.Millisecond)
	m.finish()
	s := m.Stats()
	if s.Requests != 1 || s.Answers != 1 || s.Bytes != 100 || s.Entries != 3 || s.InFlightMax != 2 {
		t.Fatalf("stats %+v", s)
	}
	// 2 for the time since inFlight(2), less for a scheduler stall before it, so the bound below is loose on purpose.
	if s.InFlightAvg <= 0.5 || s.InFlightAvg > 2 {
		t.Fatalf("InFlightAvg %v, want over 0.5 and at most 2", s.InFlightAvg)
	}
	// Once the pull has ended its length and averages stay put.
	time.Sleep(20 * time.Millisecond)
	if again := m.Stats(); again != s {
		t.Fatalf("stats moved after the end: %+v, was %+v", again, s)
	}
	m.begin()
	if s := m.Stats(); s.Requests != 0 || s.Answers != 0 || s.InFlightMax != 0 {
		t.Fatalf("a new pull did not reset the meter: %+v", s)
	}
}

// A meter belongs to one pull at a time: a second begin while the first pull runs is refused and changes nothing.
func TestMeterOnePullAtATime(t *testing.T) {
	var m PullMeter
	if !m.begin() {
		t.Fatal("begin on a fresh meter")
	}
	m.requested()
	if m.begin() {
		t.Fatal("begin while a pull uses the meter")
	}
	if s := m.Stats(); s.Requests != 1 {
		t.Fatalf("the refused begin reset the meter: %+v", s)
	}
	m.finish()
	if !m.begin() {
		t.Fatal("begin after the pull ended")
	}
}

// Pull with a meter another pull is using returns ErrInvalidArgument before it sends anything.
func TestPullMeterInUse(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ab, _ := connect(t, b, a, nil)
	r := replica(t, b, ab, a.id.PublicKey(), l.ID())
	var m PullMeter
	m.begin()
	if _, err := PullWith(testCtx(t), ab, r, &PullOptions{Meter: &m}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("PullWith = %v, want ErrInvalidArgument", err)
	}
	if r.Len() != 0 {
		t.Fatalf("%d entries pulled", r.Len())
	}
	m.finish()
	if _, err := PullWith(testCtx(t), ab, r, &PullOptions{Meter: &m}); err != nil || r.Len() != 3 {
		t.Fatalf("PullWith after the meter was free: %v, %d entries", err, r.Len())
	}
	if _, err := PullWith(testCtx(t), ab, r, &PullOptions{Meter: &m}); err != nil {
		t.Fatalf("a finished pull left the meter busy: %v", err)
	}
}

func TestFirstByteStats(t *testing.T) {
	var m PullMeter
	m.begin()
	for _, d := range []time.Duration{30, 10, 20} {
		m.firstByte(d * time.Millisecond)
	}
	m.finish()
	s := m.Stats()
	if s.FirstByteMin != 10*time.Millisecond || s.FirstByteMax != 30*time.Millisecond || s.FirstByteAvg != 20*time.Millisecond {
		t.Fatalf("first byte %v %v %v", s.FirstByteMin, s.FirstByteAvg, s.FirstByteMax)
	}
	if (PullStats{}).AvgAnswer() != 0 || (PullStats{Bytes: 10, Answers: 4}).AvgAnswer() != 2 {
		t.Fatal("AvgAnswer")
	}
}

// BenchmarkMeter is the cost the meter adds to one answer: the calls a pull makes for it.
func BenchmarkMeter(b *testing.B) {
	var m PullMeter
	m.begin()
	for range b.N {
		m.firstByte(time.Millisecond)
		m.memory(1<<20, 0)
		m.readerWait(time.Millisecond)
		m.answerRead(1<<20, 1)
		m.inFlight(3)
		m.committed(time.Millisecond, time.Millisecond)
	}
}

// Both forms of a pull count what they read, and the counts agree with what the peer sent.
func TestPullStatsCounts(t *testing.T) {
	for _, streamed := range []bool{true, false} {
		name := map[bool]string{true: "streamed", false: "one by one"}[streamed]
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			if !streamed {
				pullsOneAnswerAtATime(t)
			}
			a, b := newPeer(t), newPeer(t)
			l := sizedLog(t, a, mixedSizes(40))
			a.srv.Offer(l)
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			before := a.srv.Stats().BytesSent
			res, err := PullWith(testCtx(t), ba, r, &PullOptions{InFlight: 3})
			if err != nil {
				t.Fatal(err)
			}
			sameEntries(t, r, l)
			s := res.Stats
			sent := a.srv.Stats().BytesSent - before
			if s.Streamed != streamed || s.Entries != 40 || s.Answers < 4 || s.Elapsed <= 0 {
				t.Fatalf("stats %+v", s)
			}
			// What the server sent is the answers, the proofs and a STATE answer: little more than the answers.
			if s.Bytes+4*s.Answers > sent || sent-s.Bytes > 64<<10 {
				t.Fatalf("the server sent %d bytes, the pull counted %d of answers", sent, s.Bytes)
			}
			if s.AvgAnswer() != s.Bytes/s.Answers || s.FirstByteMin <= 0 || s.FirstByteMin > s.FirstByteAvg || s.FirstByteAvg > s.FirstByteMax {
				t.Fatalf("stats %+v", s)
			}
			if !streamed && (s.Requests != s.Answers || s.InFlightMax > 3) {
				t.Fatalf("stats %+v: one request for each answer, at most 3 in flight", s)
			}
			if s.ReaderWait <= 0 || s.CommitBusy <= 0 || s.HeldMax <= 0 || s.InFlightMax < 1 {
				t.Fatalf("stats %+v", s)
			}
		})
	}
}

// The time of the reader's waits, the first bytes' latency and the committer's busy and idle time follow what the peer and
// the store do.
func TestPullStatsTimes(t *testing.T) {
	checkGoroutines(t)
	a, c := newPeer(t), newPeer(t)
	b, _ := slowPeer(t, 30*time.Millisecond)
	c.srv = nil
	l := sizedLog(t, a, repeat(900<<10, 6))
	r := openReplica(t, b, l)
	bc, cb := connect(t, b, c, nil)
	serveStreamScript(t, cb, l, func(_ *kolotransport.Stream, kind byte, _ int, _ []byte) bool {
		if kind == 'E' {
			time.Sleep(80 * time.Millisecond)
		}
		return false
	})
	res, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 2})
	if err != nil {
		t.Fatal(err)
	}
	s := res.Stats
	if s.FirstByteMin < 80*time.Millisecond {
		t.Fatalf("FirstByteMin %v, the peer waits 80 ms before an answer", s.FirstByteMin)
	}
	if s.ReaderWait < 300*time.Millisecond {
		t.Fatalf("ReaderWait %v, the peer waits 80 ms before each of 6 answers", s.ReaderWait)
	}
	if s.CommitBusy < 30*time.Millisecond || s.CommitIdle < 200*time.Millisecond {
		t.Fatalf("CommitBusy %v CommitIdle %v", s.CommitBusy, s.CommitIdle)
	}
	if s.CommitBusy+s.CommitIdle > s.Elapsed+10*time.Millisecond {
		t.Fatalf("busy %v and idle %v over the %v of the pull", s.CommitBusy, s.CommitIdle, s.Elapsed)
	}
}

// A snapshot taken while the pull runs never goes back and never exceeds the final one, and taking them does not disturb the pull.
func TestPullMeterWhileRunning(t *testing.T) {
	checkGoroutines(t)
	a, c := newPeer(t), newPeer(t)
	b, _ := slowPeer(t, 5*time.Millisecond)
	c.srv = nil
	l := sizedLog(t, a, mixedSizes(40))
	r := openReplica(t, b, l)
	bc, cb := connect(t, b, c, nil)
	serveStreamScript(t, cb, l, func(_ *kolotransport.Stream, kind byte, _ int, _ []byte) bool {
		if kind == 'E' {
			time.Sleep(20 * time.Millisecond)
		}
		return false
	})
	var meter PullMeter
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var snaps []PullStats
	wg.Go(func() {
		for {
			snaps = append(snaps, meter.Stats())
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	})
	res, err := PullWith(testCtx(t), bc, r, &PullOptions{Meter: &meter})
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) < 5 {
		t.Fatalf("%d snapshots", len(snaps))
	}
	var prev PullStats
	for i, s := range snaps {
		if s.Bytes < prev.Bytes || s.Answers < prev.Answers || s.Elapsed < prev.Elapsed || s.Requests < prev.Requests || s.InFlightMax < prev.InFlightMax {
			t.Fatalf("snapshot %d went back: %+v after %+v", i, s, prev)
		}
		if s.Bytes > res.Stats.Bytes || s.Elapsed > res.Stats.Elapsed {
			t.Fatalf("snapshot %d is past the final one: %+v, %+v", i, s, res.Stats)
		}
		prev = s
	}
	if snaps[0].Answers == res.Stats.Answers {
		t.Fatalf("the first snapshot already held every answer")
	}
	if meter.Stats() != res.Stats {
		t.Fatal("the meter's last snapshot is not the result's")
	}
}

// A pull that fails before it reads anything still returns its stats, and a pull of a replica that is up to date has none.
func TestPullStatsOnFailure(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 5)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	ctx, cancel := context.WithCancel(testCtx(t))
	cancel()
	res, err := PullWith(ctx, ba, r, nil)
	if err == nil || res.Stats.Elapsed < 0 {
		t.Fatalf("Pull = %v, %+v", err, res.Stats)
	}
	if _, err := PullWith(testCtx(t), ba, r, &PullOptions{InFlight: -1}); err == nil {
		t.Fatal("InFlight -1 accepted")
	}
}

func TestPaceRequests(t *testing.T) {
	const mb = 1e6
	ms := time.Millisecond
	for _, tc := range []struct {
		name   string
		rate   float64
		rtt    time.Duration
		max    int
		want   int
		capped bool
	}{
		{"nothing measured", 0, 0, MaxInFlight, 2, false},
		{"loopback", 300 * mb, 200 * time.Microsecond, MaxInFlight, 2, false},
		{"slow path", 50e3, 120 * ms, MaxInFlight, 2, false},
		{"40 MB/s at 100 ms", 40 * mb, 100 * ms, MaxInFlight, 4, false},
		{"40 MB/s at 200 ms", 40 * mb, 200 * ms, MaxInFlight, 8, false},
		{"100 MB/s at 200 ms", 100 * mb, 200 * ms, MaxInFlight, 8, true},
		{"capped by InFlight", 40 * mb, 100 * ms, 3, 3, true},
		{"InFlight 2", 40 * mb, 200 * ms, 2, 2, true},
		{"InFlight 1", 40 * mb, 200 * ms, 1, 1, true},
		{"InFlight 1, slow", 0, 0, 1, 1, false},
	} {
		p := pace{rate: tc.rate, rtt: tc.rtt, maxReq: tc.max}
		if n, capped := p.requests(); n != tc.want || capped != tc.capped {
			t.Errorf("%s: %d requests, capped %v; want %d, %v", tc.name, n, capped, tc.want, tc.capped)
		}
	}
}

// The pace measures the speed over windows of at least the round trip and follows a change of it.
func TestPaceMeasuresTheRate(t *testing.T) {
	var p pace
	p.sample(0)
	p.sample(100 * time.Millisecond)
	p.sample(300 * time.Millisecond)
	if p.rtt != 100*time.Millisecond {
		t.Fatalf("rtt %v, want the shortest, 100 ms", p.rtt)
	}
	now := time.Now()
	feed := func(rate float64, d time.Duration) {
		for end := now.Add(d); now.Before(end); now = now.Add(10 * time.Millisecond) {
			p.arrived(now, int(rate*0.010))
		}
	}
	feed(40e6, 2*time.Second)
	if p.rate < 35e6 || p.rate > 45e6 {
		t.Fatalf("rate %.1f MB/s, want about 40", p.rate/1e6)
	}
	feed(2e6, 4*time.Second)
	if p.rate < 1.5e6 || p.rate > 3e6 {
		t.Fatalf("rate %.1f MB/s after the link slowed to 2", p.rate/1e6)
	}
}

// pull streams entries of 1 MiB over a link with delay each way and unlimited rate, and returns the stats.
func streamOverLink(t *testing.T, delay time.Duration, mib int) PullStats {
	t.Helper()
	oldTransport := cellTransport
	cellTransport = func() (*kolosecure.Config, func(*kolosecure.Conn)) {
		return &kolosecure.Config{Transport: &kolotransport.Config{MaxConns: 4, MaxDialed: 4, MaxStreamReceiveWindow: 8 << 20, MaxConnReceiveWindow: 16 << 20}}, nil
	}
	oldFn := pullFn
	var got PullStats
	pullFn = func(ctx context.Context, conn Conn, rep *kolostore.Replica) error {
		res, err := PullWith(ctx, conn, rep, nil)
		got = res.Stats
		return err
	}
	old := timeout
	timeout = Timeout
	t.Cleanup(func() { cellTransport, pullFn, timeout = oldTransport, oldFn, old })
	p := netsim.Profile{Delay: delay, Seed: 1}
	d := p
	d.Seed = 2
	series, _, err := pullThrough(t, mib, 1<<20, d, p, time.Minute, nil)
	if err != nil || series[len(series)-1] != uint64(mib) {
		t.Fatalf("pull: %v, %v", series, err)
	}
	return got
}

// The number of requests in flight follows the round trip: more on a long path than on a short one, never over InFlight.
func TestStreamInFlightFollowsTheRoundTrip(t *testing.T) {
	checkGoroutines(t)
	short := streamOverLink(t, 0, 24)
	long := streamOverLink(t, 40*time.Millisecond, 24)
	t.Logf("no delay: %+v", short)
	t.Logf("80 ms round trip: %+v", long)
	if !short.Streamed || !long.Streamed {
		t.Fatal("not streamed")
	}
	if short.InFlightMax > 3 {
		t.Fatalf("no delay: %d requests in flight at most, want 2 or 3", short.InFlightMax)
	}
	if long.InFlightMax <= short.InFlightMax || long.InFlightMax > MaxInFlight {
		t.Fatalf("80 ms: %d requests in flight at most, no delay %d", long.InFlightMax, short.InFlightMax)
	}
}
