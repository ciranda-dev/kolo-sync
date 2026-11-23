package kolosync

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	kolostore "github.com/ciranda-dev/kolo-store"
)

// drain asks a for the whole of l on one stream of conn, an answer at a time, and returns the entries it got and the
// code of the ERROR that ended it, 0 if none.
func drain(t *testing.T, conn Conn, a *peer, l *kolostore.Log) (got uint64, code uint64) {
	t.Helper()
	st, err := conn.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer end(st)
	if _, err := writeMsg(st, headReq(a.id.PublicKey(), l.ID())); err != nil {
		t.Fatal(err)
	}
	if m, err := readMsg(st, false); err != nil || m.typ != tHead {
		t.Fatalf("answer %+v, %v", m, err)
	}
	for got < l.Len() {
		if _, err := writeMsg(st, message{typ: tEntriesReq, a: got, b: l.Len() - 1}); err != nil {
			t.Fatal(err)
		}
		m, err := readMsg(st, false)
		if err != nil {
			t.Fatal(err)
		}
		if m.typ == tError {
			return got, m.code
		}
		got += uint64(len(m.entries))
	}
	return got, 0
}

func budgetServer(t *testing.T, rate, burst int64, sizes []int) (*peer, *kolostore.Log, *fakeClock) {
	t.Helper()
	a, l := limited(t, &ServerOptions{PeerBytesPerSecond: rate, PeerBurstBytes: burst}, sizes)
	c := newFakeClock()
	a.srv.budgets.now = c.now
	return a, l, c
}

// A peer that asks for the same log again and again is answered busy once its burst is spent, the same moment its other
// streams still work, another peer is not affected, and the peer is served again as its bucket refills.
func TestServerPeerBudget(t *testing.T) {
	checkGoroutines(t)
	const burst = 2 * MaxMessageSize
	a, l, clock := budgetServer(t, 1<<20, burst, repeat(256<<10, 16))
	b, other := newPeer(t), newPeer(t)
	conn, _ := connect(t, b, a, nil)
	oconn, _ := connect(t, other, a, nil)

	served := 0
	for ; ; served++ {
		got, code := drain(t, conn, a, l)
		if code == codeBusy {
			break
		}
		if code != 0 || got != l.Len() || served > 3 {
			t.Fatalf("pull %d: %d entries, code %d", served, got, code)
		}
	}
	if served < 1 {
		t.Fatal("the first pull of the log was refused")
	}
	if s := a.srv.Stats(); s.RefusedByLimit != 1 {
		t.Fatalf("stats %+v", s)
	}
	if got, code := drain(t, oconn, a, l); code != 0 || got != l.Len() {
		t.Fatalf("another peer: %d entries, code %d", got, code)
	}
	if _, err := FetchHeader(testCtx(t), conn, a.id.PublicKey(), l.ID()); err != nil {
		t.Fatalf("a stream of the refused connection: %v", err)
	}
	clock.advance(10 * time.Second)
	if got, code := drain(t, conn, a, l); code != 0 || got != l.Len() {
		t.Fatalf("after the bucket refilled: %d entries, code %d", got, code)
	}
}

// The budget of a peer key is shared by its connections, so a new connection does not start with a full bucket.
func TestServerPeerBudgetOverConnections(t *testing.T) {
	checkGoroutines(t)
	a, l, _ := budgetServer(t, 1<<20, 2*MaxMessageSize, repeat(256<<10, 16))
	b := newPeer(t)
	first, _ := connect(t, b, a, nil)
	for i := 0; ; i++ {
		if _, code := drain(t, first, a, l); code == codeBusy {
			break
		} else if i > 3 {
			t.Fatal("the first connection was never refused")
		}
	}
	second, _ := connect(t, b, a, nil)
	if got, code := drain(t, second, a, l); code != codeBusy || got != 0 {
		t.Fatalf("second connection: %d entries, code %d, want busy at once", got, code)
	}
}

// A pull of a log larger than the burst is refused with ErrBusy and keeps what it stored; once the bucket refills a
// pull of the same replica finishes.
func TestServerPeerBudgetPull(t *testing.T) {
	checkGoroutines(t)
	a, l, clock := budgetServer(t, 4<<20, 2*MaxMessageSize, repeat(1<<20, 12))
	b := newPeer(t)
	conn, _ := connect(t, b, a, nil)
	r := replica(t, b, conn, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), conn, r); !errors.Is(err, ErrBusy) || r.Len() == 0 || r.Len() >= l.Len() {
		t.Fatalf("Pull = %v with %d of %d entries, want ErrBusy and part of the log", err, r.Len(), l.Len())
	}
	clock.advance(10 * time.Second)
	if err := Pull(testCtx(t), conn, r); err != nil || r.Len() != l.Len() {
		t.Fatalf("Pull after the refill = %v with %d of %d entries", err, r.Len(), l.Len())
	}
}

func TestBudgets(t *testing.T) {
	clock := newFakeClock()
	b := newBudgets(100, 1000)
	b.now = clock.now
	p, q := make(ed25519.PublicKey, 32), make(ed25519.PublicKey, 32)
	q[0] = 1
	if !b.take(p, 1000) || b.take(p, 1) {
		t.Fatal("a full bucket pays its burst and no more")
	}
	if !b.take(q, 1) {
		t.Fatal("another key starts full")
	}
	clock.advance(5 * time.Second)
	if b.take(p, 501) || !b.take(p, 500) {
		t.Fatal("refill at the rate")
	}
	b.give(p, 5000)
	if !b.take(p, 1000) || b.take(p, 1) {
		t.Fatal("a refund does not pass the burst")
	}
	clock.advance(20 * time.Second)
	b.take(q, 1)
	if len(b.m) != 1 {
		t.Fatalf("%d buckets held, want only the one that is not full", len(b.m))
	}
}
