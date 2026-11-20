package kolosync

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

var noMarkers = &PullOptions{NoMarkers: true}

// deleted is a log whose owner deleted some entries after an honest peer copied it, and an empty replica of it.
type deleted struct {
	l      *kolostore.Log
	honest *kolostore.Replica // the copy taken before the deletes
	r      *kolostore.Replica
	ba, bc *kolosecure.Conn // the puller's connections to the owner and to the honest peer
}

// deleteAfterCopy makes a's log of n entries (1.5 MiB each if big), copied by c, then deleted at del by a.
func deleteAfterCopy(t *testing.T, n int, big bool, del ...uint64) deleted {
	t.Helper()
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, a, 0)
	if big {
		bigAppend(t, l, n)
	} else {
		appendN(t, l, n)
	}
	ca, _ := connect(t, c, a, nil)
	rc := replica(t, c, ca, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ca, rc); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.Offer(rc); err != nil {
		t.Fatal(err)
	}
	if len(del) > 0 {
		if err := l.Delete(del...); err != nil {
			t.Fatal(err)
		}
	}
	ba, _ := connect(t, b, a, nil)
	bc, _ := connect(t, b, c, nil)
	return deleted{l: l, honest: rc, r: replica(t, b, ba, a.id.PublicKey(), l.ID()), ba: ba, bc: bc}
}

// allLive checks that r's first n entries are live and, if keyed, hold their keys.
func allLive(t *testing.T, r *kolostore.Replica, n uint64, keyed bool) {
	t.Helper()
	for i := range n {
		info, err := r.EntryInfo(i)
		if err != nil || info.Deleted || info.Keyed != keyed {
			t.Fatalf("entry %d: %+v, %v; want live with key %v", i, info, err, keyed)
		}
	}
}

func TestNoMarkersEntries(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		big  bool
		del  []uint64
		want uint64
	}{
		{"first entry", 3, false, []uint64{0}, 0},
		{"middle", 5, false, []uint64{2, 3}, 2},
		{"last entry", 4, false, []uint64{3}, 3},
		{"inside a later chunk", 5, true, []uint64{3}, 3},
		{"first of a later chunk", 5, true, []uint64{2}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			d := deleteAfterCopy(t, tc.n, tc.big, tc.del...)
			res, err := PullWith(testCtx(t), d.ba, d.r, noMarkers)
			if !errors.Is(err, ErrMarked) || !strings.HasSuffix(err.Error(), fmt.Sprintf(": entry %d", tc.want)) {
				t.Fatalf("PullWith = %v, want ErrMarked at entry %d", err, tc.want)
			}
			if d.r.Len() != tc.want || res.KeysFrom != 0 {
				t.Fatalf("Len %d, KeysFrom %d; want %d and 0", d.r.Len(), res.KeysFrom, tc.want)
			}
			allLive(t, d.r, tc.want, true)
			if _, _, ok := d.r.Target(); tc.want == 0 && ok {
				t.Fatal("a target was stored with no entry")
			}
			res, err = PullWith(testCtx(t), d.bc, d.r, noMarkers)
			if err != nil {
				t.Fatalf("PullWith from the honest peer = %v", err)
			}
			sameEntries(t, d.r, d.honest)
			allLive(t, d.r, uint64(tc.n), true)
			if res.KeysFrom != uint64(tc.n) {
				t.Fatalf("KeysFrom %d, want %d", res.KeysFrom, tc.n)
			}
		})
	}
}

// Without NoMarkers, the same answers store the entry as deleted.
func TestPullStoresEntryMarkers(t *testing.T) {
	checkGoroutines(t)
	d := deleteAfterCopy(t, 3, false, 1)
	if err := Pull(testCtx(t), d.ba, d.r); err != nil {
		t.Fatal(err)
	}
	if _, err := d.r.Get(1); !errors.Is(err, kololog.ErrDeleted) {
		t.Fatalf("Get(1) = %v, want kololog.ErrDeleted", err)
	}
}

// A marker that is not even well formed stops the chunk just as well: it is never decoded or stored.
func TestNoMarkersForgedEntryMarker(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	if err := a.srv.Offer(tamper{Source: l, entry: func(i uint64, e *kololog.Entry) {
		if i == 1 {
			e.Marker = bytes.Repeat([]byte{7}, 200)
		}
	}}); err != nil {
		t.Fatal(err)
	}
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Pull = %v, want ErrInvalid", err)
	}
	if _, err := PullWith(testCtx(t), ba, r, noMarkers); !errors.Is(err, ErrMarked) {
		t.Fatalf("PullWith = %v, want ErrMarked", err)
	}
	if r.Len() != 1 {
		t.Fatalf("Len %d, want 1", r.Len())
	}
	if err := a.srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	if _, err := PullWith(testCtx(t), ba, r, noMarkers); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
	allLive(t, r, 3, true)
}

func TestNoMarkersState(t *testing.T) {
	for _, keyed := range []bool{true, false} {
		t.Run(fmt.Sprintf("keyed %v", keyed), func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			l := ownLog(t, a, 3)
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			pull := PullCiphertext
			if keyed {
				pull = Pull
			}
			if err := pull(testCtx(t), ba, r); err != nil {
				t.Fatal(err)
			}
			if err := l.Delete(1); err != nil {
				t.Fatal(err)
			}
			res, err := PullWith(testCtx(t), ba, r, noMarkers)
			if err != nil {
				t.Fatal(err)
			}
			for i := range uint64(3) {
				info, err := r.EntryInfo(i)
				if err != nil || info.Deleted || info.Keyed != (keyed || i != 1) {
					t.Fatalf("entry %d: %+v, %v", i, info, err)
				}
			}
			want := uint64(3)
			if !keyed {
				want = 1 // the owner no longer has entry 1's key
			}
			if res.KeysFrom != want {
				t.Fatalf("KeysFrom %d, want %d", res.KeysFrom, want)
			}
			// The marker was there to take.
			if err := Pull(testCtx(t), ba, r); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Get(1); !errors.Is(err, kololog.ErrDeleted) {
				t.Fatalf("Get(1) after Pull = %v, want kololog.ErrDeleted", err)
			}
		})
	}
}

// Markers in a STATE answer are skipped unread, so bad or misplaced ones fail nothing.
func TestNoMarkersIgnoresBadStateMarkers(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := ownLog(t, a, 4)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := PullCiphertext(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	key, err := l.Key(3)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(0, 1); err != nil {
		t.Fatal(err)
	}
	var markers [][]byte
	for i := range uint64(2) {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		markers = append(markers, e.Marker)
	}
	bad := bytes.Clone(markers[0])
	bad[len(bad)-1] ^= 1 // the signature
	items := []item{
		{index: 0, marker: bad},
		{index: 1, marker: markers[1]},
		{index: 2, marker: markers[0]}, // entry 0's marker listed at 2
		{index: 3, key: key},
	}
	h, _ := l.Head()
	bc, cb := connect(t, b, c, nil)
	serve := func() {
		rawServe(t, cb, func(st *kolotransport.Stream) {
			readMsg(st, true)
			st.Write(wire(message{typ: tHead, head: h.Encode(), header: l.Header().Encode()}))
			readMsg(st, true)
			st.Write(wire(message{typ: tState, a: 4, items: items}))
		})
	}
	serve()
	if err := Pull(testCtx(t), bc, r); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Pull = %v, want ErrProtocol", err)
	}
	serve()
	res, err := PullWith(testCtx(t), bc, r, noMarkers)
	if err != nil {
		t.Fatal(err)
	}
	for i := range uint64(4) {
		info, err := r.EntryInfo(i)
		if err != nil || info.Deleted || info.Keyed != (i == 3) {
			t.Fatalf("entry %d: %+v, %v", i, info, err)
		}
	}
	if res.KeysFrom != 0 {
		t.Fatalf("KeysFrom %d, want 0", res.KeysFrom)
	}
}

// requests returns the requests after HEAD_REQ that a pull of r sends to a server that answers every STATE_REQ
// with no items.
func requests(t *testing.T, b, c *peer, l *kolostore.Log, r *kolostore.Replica, pull func(*kolosecure.Conn) error) []message {
	t.Helper()
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
	if err := pull(bc); err != nil {
		t.Fatal(err)
	}
	return <-asked
}

// halfKeyed returns b's replica of a's 5-entry log with the keys of the first 3 entries only.
func halfKeyed(t *testing.T) (b, c *peer, l *kolostore.Log, r *kolostore.Replica) {
	t.Helper()
	a := newPeer(t)
	b, c = newPeer(t), newPeer(t)
	c.srv = nil
	l = ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r = replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2)
	if err := PullCiphertext(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	return b, c, l, r
}

func TestNoMarkersAsksOnlyForKeys(t *testing.T) {
	checkGoroutines(t)
	b, c, l, r := halfKeyed(t)
	got := requests(t, b, c, l, r, func(conn *kolosecure.Conn) error {
		_, err := PullWith(testCtx(t), conn, r, noMarkers)
		return err
	})
	if want := []message{{typ: tStateReq, a: 3, b: 4, keys: true}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("requests %+v, want %+v", got, want)
	}
}

// fingerprint is everything a replica holds: length, head, target, and each entry's flags, value and key.
func fingerprint(t *testing.T, r *kolostore.Replica) string {
	t.Helper()
	var b strings.Builder
	th, _, ok := r.Target()
	fmt.Fprintf(&b, "%s target %v %x\n", snapshot(t, r), ok, th.Encode())
	for i := range r.Len() {
		info, err := r.EntryInfo(i)
		v, verr := r.Get(i)
		k, kerr := r.Key(i)
		fmt.Fprintf(&b, "%d %+v %v %x %v %x %v\n", i, info, err, v, verr, k, kerr)
	}
	return b.String()
}

// With NoMarkers a puller ends with the honest copy whatever the owner deleted, and whichever peer it asks first.
func TestNoMarkersFinalStateIgnoresMarkers(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 0))
	for trial := range 40 {
		big := trial%4 == 0
		n := 1 + rng.IntN(7)
		if big {
			n = 3 + rng.IntN(3)
		}
		var del []uint64
		for i := range uint64(n) {
			if rng.IntN(3) == 0 {
				del = append(del, i)
			}
		}
		held := rng.IntN(n + 1)
		keyed, ownerFirst := rng.IntN(2) == 0, rng.IntN(2) == 0
		t.Run(fmt.Sprintf("n%d big %v del %v held %d keyed %v owner first %v", n, big, del, held, keyed, ownerFirst), func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			l := ownLog(t, a, 0)
			add := func(k int) {
				if big {
					bigAppend(t, l, k)
				} else {
					appendN(t, l, k)
				}
			}
			add(held)
			ba, _ := connect(t, b, a, nil)
			var r *kolostore.Replica
			if held > 0 {
				r = replica(t, b, ba, a.id.PublicKey(), l.ID())
				pull := PullCiphertext
				if keyed {
					pull = Pull
				}
				if err := pull(testCtx(t), ba, r); err != nil {
					t.Fatal(err)
				}
			}
			add(n - held)
			if r == nil {
				r = replica(t, b, ba, a.id.PublicKey(), l.ID())
			}
			ca, _ := connect(t, c, a, nil)
			rc := replica(t, c, ca, a.id.PublicKey(), l.ID())
			if err := Pull(testCtx(t), ca, rc); err != nil {
				t.Fatal(err)
			}
			c.srv.Offer(rc)
			if len(del) > 0 {
				if err := l.Delete(del...); err != nil {
					t.Fatal(err)
				}
			}
			bc, _ := connect(t, b, c, nil)
			conns := []*kolosecure.Conn{bc, ba}
			if ownerFirst {
				conns = []*kolosecure.Conn{ba, bc}
			}
			var cursor uint64
			for _, conn := range conns {
				res, err := PullWith(testCtx(t), conn, r, &PullOptions{NoMarkers: true, KeysFrom: cursor})
				if err != nil && !errors.Is(err, ErrMarked) {
					t.Fatal(err)
				}
				cursor = res.KeysFrom
			}
			if got, want := fingerprint(t, r), fingerprint(t, rc); got != want {
				t.Fatalf("replica\n%s\nwant\n%s", got, want)
			}
			allLive(t, r, uint64(n), true)
			if cursor != uint64(n) {
				t.Fatalf("KeysFrom %d, want %d", cursor, n)
			}
		})
	}
}

// The prefix before a marked entry costs one PROOF request, and the pull stops there.
func TestNoMarkersStopsAtTheMarkedEntry(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	h, _ := l.Head()
	var entries []kololog.Entry
	for i := range uint64(3) {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	p, err := l.ConsistencyProof(1, 3)
	if err != nil {
		t.Fatal(err)
	}
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
			if m.typ == tProofReq {
				st.Write(wire(message{typ: tProof, proof: p.Encode()}))
			} else {
				st.Write(wire(message{typ: tEntries, entries: entries[m.a:]}))
			}
		}
	})
	if _, err := PullWith(testCtx(t), bc, r, noMarkers); !errors.Is(err, ErrMarked) || r.Len() != 1 {
		t.Fatalf("PullWith = %v with %d entries, want ErrMarked with 1", err, r.Len())
	}
	want := []message{{typ: tEntriesReq, a: 0, b: 2, keys: true}, {typ: tProofReq, a: 1, b: 3}}
	if got := <-asked; !reflect.DeepEqual(got, want) {
		t.Fatalf("requests %+v, want %+v", got, want)
	}
}

// After ErrMarked the replica fills toward the marking peer's head: a peer behind it adds nothing and says so.
func TestNoMarkersBehindTheTarget(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	copyOf := func() *kolosecure.Conn {
		p := newPeer(t)
		pa, _ := connect(t, p, a, nil)
		rp := replica(t, p, pa, a.id.PublicKey(), l.ID())
		if err := Pull(testCtx(t), pa, rp); err != nil {
			t.Fatal(err)
		}
		if err := p.srv.Offer(rp); err != nil {
			t.Fatal(err)
		}
		bp, _ := connect(t, b, p, nil)
		return bp
	}
	at3 := copyOf()
	appendN(t, l, 7)
	at10 := copyOf()
	appendN(t, l, 1)
	at11 := copyOf()
	if err := l.Delete(5); err != nil {
		t.Fatal(err)
	}
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if _, err := PullWith(testCtx(t), ba, r, noMarkers); !errors.Is(err, ErrMarked) || r.Len() != 5 {
		t.Fatalf("PullWith from the owner = %v with %d entries, want ErrMarked with 5", err, r.Len())
	}
	for _, conn := range []*kolosecure.Conn{at10, at3} {
		res, err := PullWith(testCtx(t), conn, r, &PullOptions{NoMarkers: true, KeysFrom: 2})
		if !errors.Is(err, ErrBehind) || res.KeysFrom != 2 {
			t.Fatalf("PullWith from a peer behind = %+v, %v; want ErrBehind and KeysFrom 2", res, err)
		}
		if th, _, ok := r.Target(); r.Len() != 5 || !ok || th.Size != 11 {
			t.Fatalf("Len %d, target %v of size %d; want 5 toward 11", r.Len(), ok, th.Size)
		}
		if err := Pull(testCtx(t), conn, r); err != nil {
			t.Fatalf("Pull from a peer behind = %v, want nil", err)
		}
	}
	res, err := PullWith(testCtx(t), at11, r, noMarkers)
	if err != nil || res.KeysFrom != 11 {
		t.Fatalf("PullWith from a peer at the target = %+v, %v", res, err)
	}
	allLive(t, r, 11, true)
}

// An entry before the marker that does not verify fails the chunk: nothing is stored and the pull is not ErrMarked.
func TestNoMarkersBadEntryBeforeMarker(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := ownLog(t, a, 4)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := l.Delete(2); err != nil {
		t.Fatal(err)
	}
	h, _ := l.Head()
	var entries []kololog.Entry
	for i := range uint64(4) {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	entries[1].Ciphertext[0] ^= 1
	bc, cb := connect(t, b, c, nil)
	rawServe(t, cb, func(st *kolotransport.Stream) {
		readMsg(st, true)
		st.Write(wire(message{typ: tHead, head: h.Encode(), header: l.Header().Encode()}))
		for {
			m, err := readMsg(st, true)
			if err != nil {
				return
			}
			if m.typ == tProofReq {
				p, _ := l.ConsistencyProof(m.a, m.b)
				st.Write(wire(message{typ: tProof, proof: p.Encode()}))
			} else {
				st.Write(wire(message{typ: tEntries, entries: entries[m.a:]}))
			}
		}
	})
	_, err := PullWith(testCtx(t), bc, r, noMarkers)
	if !errors.Is(err, ErrInvalid) || errors.Is(err, ErrMarked) || r.Len() != 0 {
		t.Fatalf("PullWith = %v with %d entries, want ErrInvalid with 0", err, r.Len())
	}
	if _, _, ok := r.Target(); ok {
		t.Fatal("a target was stored")
	}
}

// A STATE item outside the entries its answer covers is still refused, marker or not.
func TestNoMarkersStateItemOutOfRange(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := ownLog(t, a, 4)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := PullCiphertext(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
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
		readMsg(st, true)
		st.Write(wire(message{typ: tState, a: 4, items: []item{{index: 4, marker: e.Marker}}}))
	})
	before := fingerprint(t, r)
	if _, err := PullWith(testCtx(t), bc, r, noMarkers); !errors.Is(err, ErrProtocol) {
		t.Fatalf("PullWith = %v, want ErrProtocol", err)
	}
	if after := fingerprint(t, r); after != before {
		t.Fatalf("replica changed:\n%s\nwas\n%s", after, before)
	}
}
