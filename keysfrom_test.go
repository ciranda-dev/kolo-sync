package kolosync

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"sync"
	"testing"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// keylessCopy returns b's replica of a's log of n entries, held without keys, and b's connection to a.
func keylessCopy(t *testing.T, a, b *peer, n int) (*kolostore.Log, *kolostore.Replica, *kolosecure.Conn) {
	t.Helper()
	l := ownLog(t, a, n)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := PullCiphertext(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	return l, r, ba
}

// keyedFrom checks that exactly the entries from i on hold their keys.
func keyedFrom(t *testing.T, r *kolostore.Replica, i uint64) {
	t.Helper()
	for j := range r.Len() {
		info, err := r.EntryInfo(j)
		if err != nil || info.Keyed != (j >= i) {
			t.Fatalf("entry %d: %+v, %v; want key %v", j, info, err, j >= i)
		}
	}
}

func TestKeysFromSkipsEarlierEntries(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	_, r, ba := keylessCopy(t, a, b, 6)
	res, err := PullWith(testCtx(t), ba, r, &PullOptions{KeysFrom: 3})
	if err != nil {
		t.Fatal(err)
	}
	keyedFrom(t, r, 3)
	if res.KeysFrom != 6 {
		t.Fatalf("KeysFrom %d, want 6", res.KeysFrom)
	}
	if res, err = PullWith(testCtx(t), ba, r, nil); err != nil || res.KeysFrom != 6 {
		t.Fatalf("PullWith = %+v, %v; want KeysFrom 6", res, err)
	}
	keyedFrom(t, r, 0)
}

func TestKeysFromRequests(t *testing.T) {
	for _, tc := range []struct {
		name  string
		keyed bool
		opts  *PullOptions
		want  []message
	}{
		{"markers", false, &PullOptions{KeysFrom: 3}, []message{{typ: tStateReq, a: 0, b: 2}, {typ: tStateReq, a: 3, b: 5, keys: true}}},
		{"no markers", false, &PullOptions{KeysFrom: 3, NoMarkers: true}, []message{{typ: tStateReq, a: 3, b: 5, keys: true}}},
		{"cursor at the end", false, &PullOptions{KeysFrom: 6, NoMarkers: true}, nil},
		{"all keyed, markers", true, &PullOptions{KeysFrom: 2}, []message{{typ: tStateReq, a: 0, b: 5}}},
		{"all keyed, no markers", true, &PullOptions{KeysFrom: 2, NoMarkers: true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			c.srv = nil
			l, r, ba := keylessCopy(t, a, b, 6)
			if tc.keyed {
				if err := Pull(testCtx(t), ba, r); err != nil {
					t.Fatal(err)
				}
			}
			got := requests(t, b, c, l, r, func(conn *kolosecure.Conn) error {
				_, err := PullWith(testCtx(t), conn, r, tc.opts)
				return err
			})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("requests %+v, want %+v", got, tc.want)
			}
		})
	}
}

// transcript is every message of one stream, both ways, in order.
type transcript [][]byte

// recorded returns b's end of a proxy to a's server that records the next stream through it.
func recorded(t *testing.T, a, b *peer) (*kolosecure.Conn, func() transcript) {
	t.Helper()
	p := newPeer(t)
	p.srv = nil
	bp, pb := connect(t, b, p, nil)
	pa, _ := connect(t, p, a, nil)
	done := make(chan transcript, 1)
	rawServe(t, pb, func(st *kolotransport.Stream) {
		var x transcript
		defer func() { done <- x }()
		up, err := pa.OpenStream(testCtx(t))
		if err != nil {
			return
		}
		defer end(up)
		for {
			req, err := readMsg(st, true)
			if err != nil {
				return
			}
			x = append(x, encode(req))
			if _, err := writeMsg(up, req); err != nil {
				return
			}
			resp, err := readMsg(up, false)
			if err != nil {
				return
			}
			x = append(x, encode(resp))
			if _, err := writeMsg(st, resp); err != nil {
				return
			}
		}
	})
	return bp, func() transcript { return <-done }
}

// samePulls builds one replica of a's log per puller, all in one state, then changes the log.
type samePulls func(t *testing.T, a *peer, bs []*peer) []*kolostore.Replica

// replicas opens each b's replica of l, pulled with pull if it is not nil.
func replicas(t *testing.T, a *peer, bs []*peer, l *kolostore.Log, pull func(context.Context, Conn, *kolostore.Replica) error) []*kolostore.Replica {
	t.Helper()
	var rs []*kolostore.Replica
	for _, b := range bs {
		ba, _ := connect(t, b, a, nil)
		r := replica(t, b, ba, a.id.PublicKey(), l.ID())
		if pull != nil {
			if err := pull(testCtx(t), ba, r); err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatal(err)
			}
		}
		rs = append(rs, r)
	}
	return rs
}

// PullWith with nil or zero options sends and gets what Pull does, message for message, and ends the same.
func TestPullWithNoOptionsIsPull(t *testing.T) {
	pullers := []func(context.Context, Conn, *kolostore.Replica) error{
		Pull,
		func(ctx context.Context, c Conn, r *kolostore.Replica) error {
			_, err := PullWith(ctx, c, r, nil)
			return err
		},
		func(ctx context.Context, c Conn, r *kolostore.Replica) error {
			_, err := PullWith(ctx, c, r, &PullOptions{})
			return err
		},
	}
	for _, sc := range []struct {
		name  string
		build samePulls
	}{
		{"one chunk", func(t *testing.T, a *peer, bs []*peer) []*kolostore.Replica {
			return replicas(t, a, bs, ownLog(t, a, 6), nil)
		}},
		{"nothing new", func(t *testing.T, a *peer, bs []*peer) []*kolostore.Replica {
			return replicas(t, a, bs, ownLog(t, a, 6), Pull)
		}},
		{"markers in entries", func(t *testing.T, a *peer, bs []*peer) []*kolostore.Replica {
			l := ownLog(t, a, 6)
			rs := replicas(t, a, bs, l, nil)
			if err := l.Delete(1, 4); err != nil {
				t.Fatal(err)
			}
			return rs
		}},
		{"many chunks with a marker", func(t *testing.T, a *peer, bs []*peer) []*kolostore.Replica {
			l := ownLog(t, a, 0)
			bigAppend(t, l, 5)
			rs := replicas(t, a, bs, l, nil)
			if err := l.Delete(3); err != nil {
				t.Fatal(err)
			}
			return rs
		}},
		{"markers in state, keys missing", func(t *testing.T, a *peer, bs []*peer) []*kolostore.Replica {
			l := ownLog(t, a, 3)
			rs := replicas(t, a, bs, l, Pull)
			appendN(t, l, 2)
			for i, b := range bs {
				ba, _ := connect(t, b, a, nil)
				if err := PullCiphertext(testCtx(t), ba, rs[i]); err != nil {
					t.Fatal(err)
				}
			}
			appendN(t, l, 2)
			if err := l.Delete(0, 4); err != nil {
				t.Fatal(err)
			}
			return rs
		}},
		{"interrupted target", func(t *testing.T, a *peer, bs []*peer) []*kolostore.Replica {
			l := ownLog(t, a, 0)
			bigAppend(t, l, 7)
			a.srv.Offer(tamper{Source: l, entry: func(i uint64, e *kololog.Entry) {
				if i >= 4 && e.Ciphertext != nil {
					e.Ciphertext[0] ^= 1
				}
			}})
			rs := replicas(t, a, bs, l, Pull)
			a.srv.Offer(l)
			appendN(t, l, 2)
			if err := l.Delete(5, 1); err != nil {
				t.Fatal(err)
			}
			return rs
		}},
	} {
		t.Run(sc.name, func(t *testing.T) {
			checkGoroutines(t)
			a := newPeer(t)
			var bs []*peer
			for range pullers {
				bs = append(bs, newPeer(t))
			}
			rs := sc.build(t, a, bs)
			var trs []transcript
			var ends []string
			for i, pull := range pullers {
				conn, tr := recorded(t, a, bs[i])
				if err := pull(testCtx(t), conn, rs[i]); err != nil {
					t.Fatalf("puller %d: %v", i, err)
				}
				trs = append(trs, tr())
				ends = append(ends, fingerprint(t, rs[i]))
			}
			if len(trs[0]) < 4 {
				t.Fatalf("Pull exchanged only %d messages", len(trs[0]))
			}
			for i := 1; i < len(pullers); i++ {
				if !reflect.DeepEqual(trs[i], trs[0]) {
					t.Errorf("puller %d: %d messages differ from Pull's %d", i, len(trs[i]), len(trs[0]))
				}
				if ends[i] != ends[0] {
					t.Errorf("puller %d ends with\n%s\nPull with\n%s", i, ends[i], ends[0])
				}
			}
		})
	}
}

func TestKeysFromResult(t *testing.T) {
	t.Run("no keys given", func(t *testing.T) {
		checkGoroutines(t)
		a, b := newPeer(t), newPeer(t)
		a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Ciphertext })
		_, r, ba := keylessCopy(t, a, b, 4)
		if res, err := PullWith(testCtx(t), ba, r, &PullOptions{KeysFrom: 2}); err != nil || res.KeysFrom != 2 {
			t.Fatalf("PullWith = %+v, %v; want KeysFrom 2", res, err)
		}
	})
	t.Run("deleted entries are passed", func(t *testing.T) {
		checkGoroutines(t)
		a, b := newPeer(t), newPeer(t)
		l, r, ba := keylessCopy(t, a, b, 4)
		if err := l.Delete(2); err != nil {
			t.Fatal(err)
		}
		if err := PullCiphertext(testCtx(t), ba, r); err != nil {
			t.Fatal(err)
		}
		if res, err := PullWith(testCtx(t), ba, r, noMarkers); err != nil || res.KeysFrom != 4 {
			t.Fatalf("PullWith = %+v, %v; want KeysFrom 4", res, err)
		}
	})
	t.Run("peer behind the cursor", func(t *testing.T) {
		checkGoroutines(t)
		a, b, c := newPeer(t), newPeer(t), newPeer(t)
		l := ownLog(t, a, 2)
		ca, _ := connect(t, c, a, nil)
		rc := replica(t, c, ca, a.id.PublicKey(), l.ID())
		if err := Pull(testCtx(t), ca, rc); err != nil {
			t.Fatal(err)
		}
		c.srv.Offer(rc)
		appendN(t, l, 3)
		ba, _ := connect(t, b, a, nil)
		r := replica(t, b, ba, a.id.PublicKey(), l.ID())
		if err := PullCiphertext(testCtx(t), ba, r); err != nil {
			t.Fatal(err)
		}
		bc, _ := connect(t, b, c, nil)
		for _, tc := range []struct{ from, want uint64 }{{4, 4}, {1, 2}} {
			if res, err := PullWith(testCtx(t), bc, r, &PullOptions{KeysFrom: tc.from}); err != nil || res.KeysFrom != tc.want {
				t.Fatalf("KeysFrom %d: PullWith = %+v, %v; want KeysFrom %d", tc.from, res, err, tc.want)
			}
		}
	})
}

func TestKeysFromPastTheReplica(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	_, r, ba := keylessCopy(t, a, b, 2)
	sent := a.srv.Stats().BytesSent
	res, err := PullWith(testCtx(t), ba, r, &PullOptions{KeysFrom: 3})
	if !errors.Is(err, ErrInvalidArgument) || res.KeysFrom != 3 {
		t.Fatalf("PullWith = %+v, %v; want ErrInvalidArgument and KeysFrom 3", res, err)
	}
	if got := a.srv.Stats().BytesSent; got != sent {
		t.Fatalf("the server sent %d bytes", got-sent)
	}
	for _, args := range []struct {
		conn *kolosecure.Conn
		rep  *kolostore.Replica
	}{{nil, r}, {ba, nil}} {
		if res, err := PullWith(testCtx(t), args.conn, args.rep, &PullOptions{KeysFrom: 1}); !errors.Is(err, ErrInvalidArgument) || res.KeysFrom != 1 {
			t.Fatalf("PullWith = %+v, %v; want ErrInvalidArgument and KeysFrom 1", res, err)
		}
	}
}

func TestKeysFromKeptOnError(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	_, r, _ := keylessCopy(t, a, b, 3)
	bc, _ := connect(t, b, c, nil)
	res, err := PullWith(testCtx(t), bc, r, &PullOptions{KeysFrom: 2})
	if !errors.Is(err, ErrNotFound) || res.KeysFrom != 2 {
		t.Fatalf("PullWith = %+v, %v; want ErrNotFound and KeysFrom 2", res, err)
	}
}

func TestPullWithConcurrentIsBusy(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	_, r, ba := keylessCopy(t, a, b, 3)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() { _, errs[i] = PullWith(testCtx(t), ba, r, noMarkers) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil && !errors.Is(err, ErrBusy) {
			t.Fatal(err)
		}
	}
	keyedFrom(t, r, 0)
}
