package kolosync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	"github.com/ciranda-dev/kolo-sync/internal/netsim"
	"github.com/ciranda-dev/kolo-sync/internal/v017"
)

// pullFn is the pull pullThrough runs, and pullStore, if not nil, makes the puller's store. oldServer, if set, serves the
// log with the code of v0.1.7. content, if not nil, appends the entries to the log instead of n of entryBytes each.
// cellTransport, if not nil, gives the config of both ends and what to do with each connection.
var (
	pullFn        = Pull
	pullStore     func(*testing.T) *kolostore.Store
	oldServer     bool
	content       func(*testing.T, *kolostore.Log)
	cellTransport func() (*kolosecure.Config, func(*kolosecure.Conn))
)

const (
	kbps = 1000 / 8
	mbps = 1000 * kbps
)

// pullThrough pulls a log of n entries of entryBytes each from a peer through a netsim link and returns the replica's
// length each 500 ms until it is complete or limit passes.
func pullThrough(t *testing.T, n, entryBytes int, up, down netsim.Profile, limit time.Duration, setup func(*netsim.Link)) ([]uint64, time.Duration, error) {
	t.Helper()
	a, b := newPeer(t), newPeer(t) // a pulls from b
	if pullStore != nil {
		a.st = pullStore(t)
	}
	l, err := b.st.Create(b.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if content != nil {
		content(t, l)
	} else {
		buf := make([]byte, entryBytes)
		rand.Read(buf)
		for range n {
			if _, err := l.Append(buf); err != nil {
				t.Fatal(err)
			}
		}
	}
	var serve func(context.Context, Conn)
	if oldServer {
		old := v017.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) v017.Access { return v017.Keys })
		if err := old.Offer(l); err != nil {
			t.Fatal(err)
		}
		serve = func(ctx context.Context, c Conn) { old.Serve(ctx, c) }
	} else {
		if err := b.srv.Offer(l); err != nil {
			t.Fatal(err)
		}
		serve = func(ctx context.Context, c Conn) { b.srv.Serve(ctx, c) }
	}
	var cfg *kolosecure.Config
	var tune func(*kolosecure.Conn)
	if cellTransport != nil {
		cfg, tune = cellTransport()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", b.id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	link, err := netsim.New(ln.Addr().String(), up, down)
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()
	if setup != nil {
		setup(link)
	}
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		if tune != nil {
			tune(c)
		}
		serve(ctx, c)
	}()
	conn, err := kolosecure.Dial(ctx, link.Addr(), a.id, b.id.PublicKey(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tune != nil {
		tune(conn)
	}
	rep := replica(t, a, conn, b.id.PublicKey(), l.ID())
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- pullFn(ctx, conn, rep) }()
	var series []uint64
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			series = append(series, rep.Len())
			return series, time.Since(start), err
		case <-tick.C:
			series = append(series, rep.Len())
			if time.Since(start) > limit {
				cancel()
				return series, time.Since(start), context.DeadlineExceeded
			}
		}
	}
}

// TestImpairedPullReport pulls a log of 1 MiB entries through a link and prints the speed; set KOLO_SYNC_IMPAIR=<MiB>,
// the size over the fast paths. The slow one, 0.4 Mbit/s, pulls 6 MiB whatever that is.
func TestImpairedPullReport(t *testing.T) {
	v := os.Getenv("KOLO_SYNC_IMPAIR")
	if v == "" {
		t.Skip("set KOLO_SYNC_IMPAIR=<MiB> to measure")
	}
	mib, _ := strconv.Atoi(v)
	old := timeout
	timeout = Timeout
	defer func() { timeout = old }()
	for _, c := range []struct {
		name  string
		rate  int
		loss  float64
		mib   int
		limit time.Duration
	}{
		{"clean", 0, 0, mib, 120 * time.Second},
		{"10 Mbps loss 1%", 10 * mbps, 0.01, min(mib, 64), 120 * time.Second},
		{"0.4 Mbps loss 0%", 400 * kbps, 0, 6, 250 * time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			up := netsim.Profile{Rate: c.rate, Delay: 60 * time.Millisecond, Jitter: 20 * time.Millisecond, Loss: c.loss, Seed: 1}
			down := up
			down.Seed = 2
			s, took, err := pullThrough(t, c.mib, 1<<20, down, up, c.limit, nil)
			got := s[len(s)-1]
			t.Logf("%s: %d of %d MiB in %v (%.2f MiB/s) err %v", c.name, got, c.mib, took.Round(time.Millisecond), float64(got)/took.Seconds(), err)
			fmt.Fprintln(os.Stderr)
		})
	}
}

// mixSizes returns the value sizes of a mixed log of about mib MiB: for each round, a run of tiny entries, a run of 4 KiB
// entries and one of 3.5 MiB, so that an answer may hold from one entry to thousands.
func mixSizes(mib int) []int {
	var sizes []int
	total := 0
	for total < mib<<20 {
		for range 300 {
			sizes = append(sizes, 64)
			total += 64
		}
		for range 400 {
			sizes = append(sizes, 4<<10)
			total += 4 << 10
		}
		sizes = append(sizes, 3<<20+512<<10)
		total += 3<<20 + 512<<10
	}
	return sizes
}

func appendSizes(t *testing.T, l *kolostore.Log, sizes []int) {
	t.Helper()
	buf := make([]byte, slices.Max(sizes))
	rand.Read(buf)
	for i, n := range sizes {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		if _, err := l.Append(buf[:n]); err != nil {
			t.Fatal(err)
		}
	}
}

// TestImpairedCell pulls a log through a link and prints one result line; set
// KOLO_SYNC_CELL=<MiB>,<RTT ms>,<Mbit/s>,<loss %>,<in-flight>,<limit s>, and KOLO_SYNC_STORE=pebble to pull into Pebble, or
// pebble-tuned for Pebble with a 256 MiB memtable and no compression, as the share app opens it (sharetransport tag).
// The link delays each direction by half of the RTT. The log is MiB entries of 1 MiB, or with KOLO_SYNC_MIX=1 about MiB of
// tiny, 4 KiB and 3.5 MiB entries. KOLO_SYNC_IMPL=old pulls and serves with the code of v0.1.7. The transport is the default,
// or the share app's with KOLO_SYNC_TRANSPORT=share and the sharetransport build tag.
func TestImpairedCell(t *testing.T) {
	v := os.Getenv("KOLO_SYNC_CELL")
	if v == "" {
		t.Skip("set KOLO_SYNC_CELL=<MiB>,<RTT ms>,<Mbit/s>,<loss %>,<in-flight>,<limit s> to measure")
	}
	f := strings.Split(v, ",")
	if len(f) != 6 {
		t.Fatalf("KOLO_SYNC_CELL %q: want 6 fields", v)
	}
	num := func(i int) float64 {
		x, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			t.Fatalf("KOLO_SYNC_CELL field %d: %v", i, err)
		}
		return x
	}
	mib, rtt, rate, loss, depth, limit := int(num(0)), num(1), num(2), num(3), int(num(4)), num(5)
	old := timeout
	timeout = Timeout
	defer func() { timeout = old }()
	delay := time.Duration(rtt / 2 * float64(time.Millisecond))
	up := netsim.Profile{Rate: int(rate * mbps), Delay: delay, Loss: loss / 100, Seed: 1}
	down := up
	down.Seed = 2
	var stats PullStats
	oldImpl := os.Getenv("KOLO_SYNC_IMPL") == "old"
	oldServer = oldImpl
	pullFn = func(ctx context.Context, conn Conn, rep *kolostore.Replica) error {
		if oldImpl {
			_, err := v017.PullWith(ctx, conn, rep, &v017.PullOptions{InFlight: depth})
			return err
		}
		res, err := PullWith(ctx, conn, rep, &PullOptions{InFlight: depth})
		stats = res.Stats
		return err
	}
	defer func() { pullFn, pullStore, oldServer, content, cellTransport = Pull, nil, false, nil, nil }()
	entry, entries := 1<<20, mib
	var sizes []int
	if os.Getenv("KOLO_SYNC_MIX") != "" {
		sizes = mixSizes(mib)
		content = func(t *testing.T, l *kolostore.Log) { appendSizes(t, l, sizes) }
		entries = len(sizes)
	}
	if tr := os.Getenv("KOLO_SYNC_TRANSPORT"); tr != "" {
		cellTransport = transportNamed(t, tr)
	}
	if kind := os.Getenv("KOLO_SYNC_STORE"); kind == "pebble" || kind == "pebble-tuned" {
		pullStore = func(t *testing.T) *kolostore.Store {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			open := kolostore.OpenPebble
			if kind == "pebble-tuned" {
				open = tunedPebble
			}
			be, err := open(dir)
			if err != nil {
				t.Fatal(err)
			}
			st := kolostore.New(be)
			t.Cleanup(func() { st.Close() })
			return st
		}
	}
	s, took, err := pullThrough(t, entries, entry, down, up, time.Duration(limit*float64(time.Second)), nil)
	got := int(s[len(s)-1])
	var bytes, total float64
	if sizes == nil {
		bytes, total = float64(got)*(1<<20), float64(entries)*(1<<20)
	} else {
		for i, n := range sizes {
			total += float64(n)
			if i < got {
				bytes += float64(n)
			}
		}
	}
	fmt.Printf("CELL impl=%s mix=%v transport=%q rtt=%vms rate=%vMbit loss=%v%% inflight=%d: %d of %d entries (%.1f MB) in %.1fs = %.2f MB/s err=%v\n",
		map[bool]string{true: "old", false: "new"}[oldImpl], sizes != nil, os.Getenv("KOLO_SYNC_TRANSPORT"), rtt, rate, loss, depth, got, entries, total/1e6, took.Seconds(), bytes/1e6/took.Seconds(), err)
	if !oldImpl {
		fmt.Printf("STATS %+v\n", stats)
	}
}
