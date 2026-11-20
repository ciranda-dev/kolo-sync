package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func held(keys []kololog.EntryKey, start uint64) func(uint64) (kololog.EntryKey, error) {
	return func(i uint64) (kololog.EntryKey, error) {
		if i < start || i-start >= uint64(len(keys)) {
			return nil, nil
		}
		return slices.Clone(keys[i-start]), nil
	}
}

// pinOf makes p a pin of l: a replica pulled with PullCiphertext, served to everyone with Ciphertext access.
func pinOf(t *testing.T, p, owner *peer, l *kolostore.Log) *kolostore.Replica {
	t.Helper()
	p.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Ciphertext })
	po, _ := connect(t, p, owner, nil)
	r := replica(t, p, po, owner.id.PublicKey(), l.ID())
	if err := PullCiphertext(testCtx(t), po, r); err != nil {
		t.Fatal(err)
	}
	po.Close()
	for i := range r.Len() {
		if info, err := r.EntryInfo(i); err != nil || info.Keyed {
			t.Fatalf("the pin holds the key of entry %d (%v)", i, err)
		}
	}
	if err := p.srv.Offer(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// Alice gives Bob her keys; with Alice gone, Bob reads entries from a pin that holds ciphertext only.
func TestReadFromPinWithHeldKeys(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 6)
	if err := l.Delete(2); err != nil {
		t.Fatal(err)
	}
	pinOf(t, pin, alice, l)
	ba, _ := connect(t, bob, alice, nil)
	h, err := FetchHead(testCtx(t), ba, alice.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := FetchKeys(testCtx(t), ba, h, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 6 || keys[2] != nil {
		t.Fatalf("%d keys, key of the deleted entry %v", len(keys), keys[2] != nil)
	}
	for i, k := range keys {
		if want, err := l.Key(uint64(i)); err == nil && !bytes.Equal(k, want) {
			t.Fatalf("key %d differs", i)
		}
	}
	ba.Close()
	alice.srv = nil

	bp, _ := connect(t, bob, pin, nil)
	if got, err := Fetch(testCtx(t), bp, h, 3, 3); err != nil || !errors.Is(got[0].Err, kololog.ErrKeyUnavailable) {
		t.Fatalf("Fetch from the pin without keys = %+v, %v; want kololog.ErrKeyUnavailable", got, err)
	}
	got, err := FetchWithKeys(testCtx(t), bp, h, 1, 4, held(keys, 0))
	if err != nil {
		t.Fatal(err)
	}
	if f := got[1]; f.Index != 2 || !errors.Is(f.Err, kololog.ErrDeleted) {
		t.Fatalf("deleted entry: %+v", f)
	}
	sameValues(t, got[:1], l, 1, 1)
	sameValues(t, got[2:], l, 3, 4)
}

func readRaw(st *kolotransport.Stream) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(st, h[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.LittleEndian.Uint32(h[:]))
	if _, err := io.ReadFull(st, b); err != nil {
		return nil, err
	}
	return b, nil
}

// keyless serves src and fails the test if it is ever asked for a key or holds one.
type keyless struct {
	Source
	t *testing.T
}

func (s keyless) Key(i uint64) (kololog.EntryKey, error) {
	s.t.Errorf("the pin was asked for the key of entry %d", i)
	return nil, kololog.ErrKeyUnavailable
}

func (s keyless) Entry(i uint64) (kololog.Entry, error) {
	e, err := s.Source.Entry(i)
	if len(e.Key) != 0 {
		s.t.Errorf("the pin holds the key of entry %d", i)
	}
	return e, err
}

// rawPin answers the next stream on conn as a pin of src: HEAD, then each FETCH_REQ with the honest FETCH
// answer, or with the frame change returns for it, ending the stream after a truncated one. It scans every byte it receives for every key in keys.
func rawPin(t *testing.T, conn *kolosecure.Conn, src Source, keys []kololog.EntryKey, change func(m message) []byte) {
	t.Helper()
	rawServe(t, conn, func(st *kolotransport.Stream) {
		head, err := src.Head()
		if err != nil {
			t.Error(err)
			return
		}
		for n := 0; ; n++ {
			b, err := readRaw(st)
			if err != nil {
				return
			}
			for i, k := range keys {
				if len(k) != 0 && bytes.Contains(b, k) {
					t.Errorf("the pin received the key of entry %d", i)
				}
			}
			m, err := decode(b, true)
			if err != nil {
				t.Error(err)
				return
			}
			var resp message
			switch {
			case n == 0 && m.typ == tHeadReq:
				resp = message{typ: tHead, head: head.Encode(), header: src.Header().Encode()}
			case m.typ == tFetchReq:
				var code uint64
				if resp, code = entries(src, false, m.a, m.b, m.size); code != 0 {
					resp = message{typ: tError, code: code}
				}
				if change != nil {
					f := change(resp)
					st.Write(f)
					if len(f) < 4 || int(binary.LittleEndian.Uint32(f))+4 != len(f) {
						return // a truncated frame ends the stream
					}
					continue
				}
			default:
				t.Errorf("the pin got a request of type %d", m.typ)
				return
			}
			st.Write(wire(resp))
		}
	})
}

// TestPinNeverSeesAKey reads through a pin double that scans every received byte for every key in play.
func TestPinNeverSeesAKey(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 1)
	bigAppend(t, l, 3) // two answers
	r := pinOf(t, pin, alice, l)
	var all []kololog.EntryKey
	for i := range l.Len() {
		k, err := l.Key(i)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, k)
	}
	h := trusted(t, l)
	pin.srv = nil
	bp, pb := connect(t, bob, pin, nil)
	rawPin(t, pb, keyless{r, t}, all, nil)
	got, err := FetchWithKeys(testCtx(t), bp, h, 0, 3, held(all, 0))
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 0, 3)
}

func TestHostilePin(t *testing.T) {
	type tc struct {
		change func(m message) []byte
		keys   func(all []kololog.EntryKey) func(uint64) (kololog.EntryKey, error)
		want   []error
		not    error
	}
	alter := func(f func(*message)) func(m message) []byte {
		return func(m message) []byte { f(&m); return wire(m) }
	}
	var marker []byte // the delete marker of entry 1, set by each subtest
	cases := map[string]tc{
		"wrong ciphertext": {change: alter(func(m *message) { m.entries[0].Ciphertext[0] ^= 1 }), want: []error{ErrInvalid, kololog.ErrBadEntry}, not: ErrKeyMismatch},
		"wrong proof": {change: alter(func(m *message) {
			p, _ := kololog.DecodeInclusionProof(m.proofs[0])
			p.Path[0][0] ^= 1
			m.proofs[0] = p.Encode()
		}), want: []error{ErrInvalid, kololog.ErrBadProof}},
		"proof for another size": {change: alter(func(m *message) {
			p, _ := kololog.DecodeInclusionProof(m.proofs[0])
			p.Size--
			m.proofs[0] = p.Encode()
		}), want: []error{ErrInvalid, kololog.ErrBadProof}},
		"swap entries and proofs": {change: alter(func(m *message) {
			m.entries[0], m.entries[1] = m.entries[1], m.entries[0]
			m.proofs[0], m.proofs[1] = m.proofs[1], m.proofs[0]
		}), want: []error{ErrInvalid}},
		"swap entries only": {change: alter(func(m *message) { m.entries[0], m.entries[1] = m.entries[1], m.entries[0] }), want: []error{ErrInvalid}},
		"record of another index": {change: alter(func(m *message) {
			m.entries[0] = kololog.Entry{Record: m.entries[1].Record, Ciphertext: m.entries[1].Ciphertext}
		}), want: []error{ErrInvalid}},
		"deleted with another entry's marker": {change: alter(func(m *message) {
			m.entries[0].Ciphertext, m.entries[0].Marker = nil, marker
		}), want: []error{ErrInvalid}},
		"marker and ciphertext":    {change: alter(func(m *message) { m.entries[0].Marker = marker }), want: []error{ErrInvalid}},
		"no ciphertext, no marker": {change: alter(func(m *message) { m.entries[0].Ciphertext = nil }), want: []error{ErrInvalid}},
		"no entries":               {change: alter(func(m *message) { m.entries, m.proofs = nil, nil }), want: []error{ErrProtocol}},
		"extra entries":            {change: alter(func(m *message) { m.entries, m.proofs = append(m.entries, m.entries[0]), append(m.proofs, m.proofs[0]) }), want: []error{ErrProtocol}},
		"truncated":                {change: func(m message) []byte { w := wire(m); return w[:len(w)/2] }, want: []error{ErrProtocol}},
		"a key in the answer that does not match": {change: alter(func(m *message) { m.entries[0].Key = bytes.Repeat([]byte{7}, keySize) }), want: []error{ErrInvalid, kololog.ErrBadEntry}},
		"key source fails": {keys: func([]kololog.EntryKey) func(uint64) (kololog.EntryKey, error) {
			return func(uint64) (kololog.EntryKey, error) { return nil, errDisk }
		}, want: []error{errDisk}, not: ErrInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
			l := ownLog(t, alice, 4)
			if err := l.Delete(1); err != nil {
				t.Fatal(err)
			}
			e1, err := l.Entry(1)
			if err != nil {
				t.Fatal(err)
			}
			marker = e1.Marker
			r := pinOf(t, pin, alice, l)
			var all []kololog.EntryKey
			for i := range l.Len() {
				k, _ := l.Key(i)
				all = append(all, k)
			}
			keys := held(all, 0)
			if c.keys != nil {
				keys = c.keys(all)
			}
			pin.srv = nil
			bp, pb := connect(t, bob, pin, nil)
			rawPin(t, pb, r, all, c.change)
			got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 2, 3, keys)
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Fatalf("FetchWithKeys = %v, want %v", err, c.want)
				}
			}
			if c.not != nil && errors.Is(err, c.not) {
				t.Fatalf("FetchWithKeys = %v, must not be %v", err, c.not)
			}
			if got != nil {
				t.Fatalf("FetchWithKeys returned %d entries with an error", len(got))
			}
		})
	}
}

func TestHeldKeyOnlyWhenNoneSent(t *testing.T) {
	checkGoroutines(t)
	alice, bob := newPeer(t), newPeer(t)
	l := ownLog(t, alice, 3)
	ba, _ := connect(t, bob, alice, nil)
	asked := 0
	got, err := FetchWithKeys(testCtx(t), ba, trusted(t, l), 0, 2, func(uint64) (kololog.EntryKey, error) {
		asked++
		return nil, errDisk
	})
	if err != nil || asked != 0 {
		t.Fatalf("FetchWithKeys from a peer with Keys = %v after %d key requests", err, asked)
	}
	sameValues(t, got, l, 0, 2)

	// No key held: the entry is reported as without its key, and the source's copy is cleared after use.
	pin := newPeer(t)
	pinOf(t, pin, alice, l)
	bp, _ := connect(t, bob, pin, nil)
	var given []kololog.EntryKey
	got, err = FetchWithKeys(testCtx(t), bp, trusted(t, l), 0, 2, func(i uint64) (kololog.EntryKey, error) {
		if i == 1 {
			return nil, nil
		}
		k, err := l.Key(i)
		given = append(given, k)
		return k, err
	})
	if err != nil || !errors.Is(got[1].Err, kololog.ErrKeyUnavailable) || got[1].Data != nil {
		t.Fatalf("FetchWithKeys = %+v, %v", got, err)
	}
	sameValues(t, got[:1], l, 0, 0)
	sameValues(t, got[2:], l, 2, 2)
	for _, k := range given {
		if !bytes.Equal(k, make([]byte, keySize)) {
			t.Fatal("a held key was not cleared after use")
		}
	}
}

func TestFetchKeys(t *testing.T) {
	for _, access := range []Access{Ciphertext, Keys} {
		t.Run(fmt.Sprint(access), func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return access })
			l := ownLog(t, a, 4)
			if err := l.Delete(1); err != nil {
				t.Fatal(err)
			}
			ba, _ := connect(t, b, a, nil)
			keys, err := FetchKeys(testCtx(t), ba, trusted(t, l), 1, 3)
			if err != nil || len(keys) != 3 {
				t.Fatalf("FetchKeys = %d keys, %v", len(keys), err)
			}
			for j, k := range keys {
				want, _ := l.Key(1 + uint64(j))
				if access == Ciphertext {
					want = nil
				}
				if !bytes.Equal(k, want) || (want == nil) != (k == nil) {
					t.Fatalf("key of entry %d: %x, want %x", 1+j, k, want)
				}
			}
		})
	}
}

func TestFetchKeysArgumentsAndHead(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	base, ra, _ := forks(t, a.id, 2, 2, 0)
	a.srv.Offer(base)
	ba, _ := connect(t, b, a, nil)
	h := trusted(t, ra)
	for name, err := range map[string]error{
		"nil conn":      second(FetchKeys(testCtx(t), nil, h, 0, 0)),
		"past the head": second(FetchKeys(testCtx(t), ba, h, 0, 4)),
		"zero head":     second(FetchKeys(testCtx(t), ba, kololog.VerifiedHead{}, 0, 0)),
	} {
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", name, err)
		}
	}
	if _, err := FetchKeys(testCtx(t), ba, h, 0, 1); !errors.Is(err, ErrBehind) {
		t.Fatalf("FetchKeys from a peer behind = %v, want ErrBehind", err)
	}
	if _, err := FetchWithKeys(testCtx(t), nil, h, 0, 0, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("FetchWithKeys(nil conn) = %v", err)
	}
}

// FetchKeys asks again where a STATE answer stopped, and refuses answers that do not move on or list items outside them.
func TestFetchKeysAnswers(t *testing.T) {
	key := func(c byte) []byte { return bytes.Repeat([]byte{c}, keySize) }
	for name, tc := range map[string]struct {
		answers []message
		want    error
		keys    [][]byte
	}{
		"in two answers": {answers: []message{
			{typ: tState, a: 2, items: []item{{index: 1, key: key(1)}}},
			{typ: tState, a: 4, items: []item{{index: 3, key: key(3)}}},
		}, keys: [][]byte{nil, key(1), nil, key(3)}},
		"no progress":     {answers: []message{{typ: tState, a: 0}}, want: ErrProtocol},
		"past the range":  {answers: []message{{typ: tState, a: 5}}, want: ErrProtocol},
		"item past next":  {answers: []message{{typ: tState, a: 2, items: []item{{index: 2, key: key(2)}}}}, want: ErrProtocol},
		"unexpected type": {answers: []message{{typ: tProof, proof: []byte{0}}}, want: ErrProtocol},
		"error after keys": {answers: []message{
			{typ: tState, a: 2, items: []item{{index: 1, key: key(1)}}},
			{typ: tError, code: codeBusy},
		}, want: ErrBusy},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			l := ownLog(t, a, 4)
			c.srv = nil
			hh, _ := l.Head()
			bc, cb := connect(t, b, c, nil)
			asked := make(chan int, 1)
			rawServe(t, cb, func(st *kolotransport.Stream) {
				readMsg(st, true)
				st.Write(wire(message{typ: tHead, head: hh.Encode(), header: l.Header().Encode()}))
				n := 0
				defer func() { asked <- n }()
				for _, m := range append(tc.answers, tc.answers[len(tc.answers)-1]) {
					if _, err := readMsg(st, true); err != nil {
						return
					}
					n++
					st.Write(wire(m))
				}
			})
			got, err := FetchKeys(testCtx(t), bc, trusted(t, l), 0, 3)
			// The server repeats its last answer once more; a client stops at the first bad one.
			if n := <-asked; n != len(tc.answers) {
				t.Fatalf("the client sent %d requests, want %d", n, len(tc.answers))
			}
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("FetchKeys = %v, want %v", err, tc.want)
			}
			if tc.want != nil && got != nil {
				t.Fatal("keys returned with an error")
			}
			if tc.want == nil && !slices.EqualFunc(got, tc.keys, func(a kololog.EntryKey, b []byte) bool { return bytes.Equal(a, b) && (a == nil) == (b == nil) }) {
				t.Fatalf("keys %x, want %x", got, tc.keys)
			}
		})
	}
}

// A key source that wraps kololog.ErrKeyUnavailable holds no key: the entry is reported, the call goes on.
// Log.Key and Replica.Key fit as key sources.
func TestKeySourceWithoutKey(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 3)
	rp := pinOf(t, pin, alice, l)
	bp, _ := connect(t, bob, pin, nil)
	h := trusted(t, l)
	for name, keys := range map[string]func(uint64) (kololog.EntryKey, error){
		"wrapped sentinel":     func(uint64) (kololog.EntryKey, error) { return nil, fmt.Errorf("store: %w", kololog.ErrKeyUnavailable) },
		"replica without keys": rp.Key,
	} {
		got, err := FetchWithKeys(testCtx(t), bp, h, 0, 2, keys)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, f := range got {
			if f.Err != kololog.ErrKeyUnavailable || f.Data != nil {
				t.Fatalf("%s: entry %d: %+v, want kololog.ErrKeyUnavailable", name, f.Index, f)
			}
		}
	}
	got, err := FetchWithKeys(testCtx(t), bp, h, 0, 2, l.Key)
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 0, 2)
}

// A key source that knows an entry is deleted, or is past its own copy of the log, reports that entry alone.
func TestKeySourceDeletedOrPast(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 3)
	pinOf(t, pin, alice, l)
	bp, _ := connect(t, bob, pin, nil)
	keys := func(i uint64) (kololog.EntryKey, error) {
		switch i {
		case 0:
			return nil, fmt.Errorf("replica: %w", kololog.ErrDeleted)
		case 2:
			return nil, fmt.Errorf("replica: %w", kololog.ErrOutOfRange)
		}
		return l.Key(i)
	}
	got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 0, 2, keys)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := l.Get(1)
	if got[0].Err != kololog.ErrDeleted || got[2].Err != kololog.ErrKeyUnavailable || got[1].Err != nil || !bytes.Equal(got[1].Data, want) {
		t.Fatalf("got %+v", got)
	}
}

// keyRange zeroes the keys it got before every error it returns.
func TestKeyRangeClearsOnError(t *testing.T) {
	key := bytes.Repeat([]byte{9}, keySize)
	first := message{typ: tState, a: 2, items: []item{{index: 1, key: key}}}
	for name, bad := range map[string]message{
		"error answer":    {typ: tError, code: codeBusy},
		"no progress":     {typ: tState, a: 2},
		"item past next":  {typ: tState, a: 3, items: []item{{index: 3, key: key}}},
		"past the range":  {typ: tState, a: 9},
		"repeated index":  {typ: tState, a: 3, items: []item{{index: 2, key: key}, {index: 2, key: key}}},
		"out of order":    {typ: tState, a: 4, items: []item{{index: 3, key: key}, {index: 2, key: key}}},
		"unexpected type": {typ: tProof, proof: []byte{0}},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			l := ownLog(t, a, 4)
			c.srv = nil
			hh, _ := l.Head()
			bc, cb := connect(t, b, c, nil)
			rawServe(t, cb, func(st *kolotransport.Stream) {
				readMsg(st, true)
				st.Write(wire(message{typ: tHead, head: hh.Encode(), header: l.Header().Encode()}))
				for _, m := range []message{first, bad} {
					if _, err := readMsg(st, true); err != nil {
						return
					}
					st.Write(wire(m))
				}
			})
			cl, ph, _, err := open(testCtx(t), bc, a.id.PublicKey(), l.ID())
			if err != nil {
				t.Fatal(err)
			}
			defer cl.close()
			out, err := cl.keyRange(trusted(t, l), ph, 0, 3)
			if err == nil {
				t.Fatal("keyRange accepted a bad answer")
			}
			if len(out) < 2 || out[1] == nil {
				t.Fatalf("keyRange returned %d keys, want the partial ones", len(out))
			}
			for i, k := range out {
				if k != nil && !bytes.Equal(k, make([]byte, keySize)) {
					t.Fatalf("key %d not cleared after %v", i, err)
				}
			}
		})
	}
}

// A later FETCH answer that fails, or a later bad entry in an answer, clears the values already opened.
func TestFetchRangeClearsOnError(t *testing.T) {
	for name, bad := range map[string]func(m *message){
		"error answer": func(m *message) { *m = message{typ: tError, code: codeBusy} },
		"bad entry": func(m *message) {
			m.entries[1].Ciphertext = slices.Clone(m.entries[1].Ciphertext)
			m.entries[1].Ciphertext[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			l := ownLog(t, a, 4)
			c.srv = nil
			bc, cb := connect(t, b, c, nil)
			rawServe(t, cb, func(st *kolotransport.Stream) {
				hh, _ := l.Head()
				readMsg(st, true)
				st.Write(wire(message{typ: tHead, head: hh.Encode(), header: l.Header().Encode()}))
				for n := 0; ; n++ {
					req, err := readMsg(st, true)
					if err != nil {
						return
					}
					m, code := entries(l, true, req.a, req.b, req.size)
					if code != 0 {
						return
					}
					if n == 0 {
						m.entries, m.proofs = m.entries[:2], m.proofs[:2]
					} else {
						bad(&m)
					}
					st.Write(wire(m))
				}
			})
			cl, ph, _, err := open(testCtx(t), bc, a.id.PublicKey(), l.ID())
			if err != nil {
				t.Fatal(err)
			}
			defer cl.close()
			out, _, err := cl.fetchRange(trusted(t, l), ph, 0, 3, false)
			if err == nil {
				t.Fatal("fetchRange accepted a bad answer")
			}
			if len(out) < 2 || len(out[0].Data) == 0 {
				t.Fatalf("fetchRange returned %d entries, want the ones before the error", len(out))
			}
			for i, f := range out {
				if !bytes.Equal(f.Data, make([]byte, len(f.Data))) {
					t.Fatalf("value %d not cleared after %v", i, err)
				}
			}
		})
	}
}

// A held key that does not match its entry is reported for that entry only; the other entries open.
func TestKeyMismatchPerEntry(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 4)
	r := pinOf(t, pin, alice, l)
	all := keysOf(t, l)
	pin.srv = nil
	bp, pb := connect(t, bob, pin, nil)
	rawPin(t, pb, r, all, nil)
	var given []kololog.EntryKey
	got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 1, 3, func(i uint64) (kololog.EntryKey, error) {
		k := slices.Clone(all[i])
		if i == 2 {
			k = slices.Clone(all[0])
		}
		given = append(given, k)
		return k, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !errors.Is(got[1].Err, ErrKeyMismatch) || !errors.Is(got[1].Err, kololog.ErrBadEntry) || got[1].Data != nil {
		t.Fatalf("FetchWithKeys = %+v, want entry 2 reported with ErrKeyMismatch", got)
	}
	if errors.Is(got[1].Err, ErrInvalid) {
		t.Fatalf("a held key mismatch is not the peer's fault: %v", got[1].Err)
	}
	for _, k := range all {
		if bytes.Contains([]byte(got[1].Err.Error()), k) {
			t.Fatal("a key is in the error")
		}
	}
	sameValues(t, got[:1], l, 1, 1)
	sameValues(t, got[2:], l, 3, 3)
	for i, k := range given {
		if !bytes.Equal(k, make([]byte, keySize)) {
			t.Fatalf("held key %d not cleared", i)
		}
	}
}

// Held keys are used only after the last answer, so the pace of the stream does not depend on them.
func TestHeldKeysUsedAfterLastAnswer(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 4)
	r := pinOf(t, pin, alice, l)
	all := keysOf(t, l)
	pin.srv = nil
	bp, pb := connect(t, bob, pin, nil)
	var answers atomic.Int64
	rawPin(t, pb, r, all, func(m message) []byte {
		m.entries, m.proofs = m.entries[:1], m.proofs[:1]
		answers.Add(1)
		return wire(m)
	})
	src := held(all, 0)
	got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 0, 3, func(i uint64) (kololog.EntryKey, error) {
		if n := answers.Load(); n != 4 {
			t.Errorf("key of entry %d asked after %d of 4 answers", i, n)
		}
		return src(i)
	})
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 0, 3)
}

func keysOf(t *testing.T, l *kolostore.Log) []kololog.EntryKey {
	t.Helper()
	var all []kololog.EntryKey
	for i := range l.Len() {
		k, err := l.Key(i)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, k)
	}
	return all
}

// A STATE item below the index the answer starts at or below the range, a repeated item and items out of
// order are protocol errors, not a panic or a key left behind.
func TestFetchKeysBadItems(t *testing.T) {
	key := bytes.Repeat([]byte{5}, keySize)
	for name, answers := range map[string][]message{
		"below next":   {{typ: tState, a: 3, items: []item{{index: 2, key: key}}}, {typ: tState, a: 4, items: []item{{index: 1, key: key}}}},
		"below start":  {{typ: tState, a: 3, items: []item{{index: 2, key: key}}}, {typ: tState, a: 4, items: []item{{index: 0, key: key}}}},
		"repeated":     {{typ: tState, a: 4, items: []item{{index: 2, key: key}, {index: 2, key: key}}}},
		"out of order": {{typ: tState, a: 4, items: []item{{index: 2, key: key}, {index: 1, key: key}}}},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			l := ownLog(t, a, 4)
			c.srv = nil
			hh, _ := l.Head()
			bc, cb := connect(t, b, c, nil)
			rawServe(t, cb, func(st *kolotransport.Stream) {
				readMsg(st, true)
				st.Write(wire(message{typ: tHead, head: hh.Encode(), header: l.Header().Encode()}))
				for _, m := range answers {
					if _, err := readMsg(st, true); err != nil {
						return
					}
					for i := range m.items {
						m.items[i].key = slices.Clone(m.items[i].key)
					}
					st.Write(wire(m))
				}
				readMsg(st, true)
			})
			got, err := FetchKeys(testCtx(t), bc, trusted(t, l), 1, 3)
			if !errors.Is(err, ErrProtocol) || got != nil {
				t.Fatalf("FetchKeys = %x, %v; want ErrProtocol", got, err)
			}
		})
	}
}

// A STATE answer that covers more entries than one answer may scan is a protocol error.
func TestStateEndBounds(t *testing.T) {
	const next, end = 7, 1 << 40
	for _, c := range []struct {
		a  uint64
		ok bool
	}{{next, false}, {next + 1, true}, {next + maxScan, true}, {next + maxScan + 1, false}, {end + 1, false}} {
		if err := stateEnd(c.a, next, end); (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrProtocol)) {
			t.Errorf("stateEnd(%d) = %v, want ok %v", c.a, err, c.ok)
		}
	}
	if err := stateEnd(10, 7, 9); err != nil {
		t.Errorf("stateEnd at end+1 = %v", err)
	}
}

// The pin sees the stream end before any held key is used, so the time of the end does not depend on them.
func TestHeldKeysUsedAfterStreamEnds(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 3)
	r := pinOf(t, pin, alice, l)
	all := keysOf(t, l)
	pin.srv = nil
	bp, pb := connect(t, bob, pin, nil)
	ended := make(chan struct{})
	rawServe(t, pb, func(st *kolotransport.Stream) {
		head, _ := r.Head()
		for {
			m, err := readMsg(st, true)
			if err != nil {
				if !errors.Is(err, ErrTimeout) {
					close(ended) // the stream ended; a read timeout is not an end
				}
				return
			}
			resp := message{typ: tHead, head: head.Encode(), header: r.Header().Encode()}
			if m.typ == tFetchReq {
				resp, _ = entries(r, false, m.a, m.b, m.size)
			}
			st.Write(wire(resp))
		}
	})
	src := held(all, 0)
	got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 0, 2, func(i uint64) (kololog.EntryKey, error) {
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Errorf("key of entry %d asked before the pin saw the stream end", i)
		}
		return src(i)
	})
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 0, 2)
}

// A key source that fails partway fails the call: the keys given before are cleared, no later key is asked.
func TestKeySourceFailsPartway(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 4)
	pinOf(t, pin, alice, l)
	all := keysOf(t, l)
	bp, _ := connect(t, bob, pin, nil)
	var given []kololog.EntryKey
	var asked []uint64
	got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 0, 3, func(i uint64) (kololog.EntryKey, error) {
		asked = append(asked, i)
		if i == 1 {
			return nil, errDisk
		}
		k := slices.Clone(all[i])
		given = append(given, k)
		return k, nil
	})
	if !errors.Is(err, errDisk) || got != nil {
		t.Fatalf("FetchWithKeys = %d entries, %v; want errDisk", len(got), err)
	}
	if want := "kolosync: key of entry 1: disk error"; err.Error() != want {
		t.Fatalf("error %q, want %q", err, want)
	}
	if !slices.Equal(asked, []uint64{0, 1}) {
		t.Fatalf("keys asked for %v, want [0 1]", asked)
	}
	for i, k := range given {
		if !bytes.Equal(k, make([]byte, keySize)) {
			t.Fatalf("key %d not cleared", i)
		}
	}
}

// Once ctx is done, FetchWithKeys asks for no more held keys and returns ctx.Err().
func TestHeldKeysStopWithContext(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 3)
	pinOf(t, pin, alice, l)
	all := keysOf(t, l)
	bp, _ := connect(t, bob, pin, nil)
	ctx, cancel := context.WithCancel(testCtx(t))
	asked := 0
	got, err := FetchWithKeys(ctx, bp, trusted(t, l), 0, 2, func(i uint64) (kololog.EntryKey, error) {
		asked++
		cancel()
		return slices.Clone(all[i]), nil
	})
	if !errors.Is(err, context.Canceled) || got != nil || asked != 1 {
		t.Fatalf("FetchWithKeys = %d entries, %v after %d keys; want context.Canceled after 1", len(got), err, asked)
	}
}

// openAllHeld clears the values it opened before it returns an error.
func TestOpenAllHeldClearsOnError(t *testing.T) {
	a := newPeer(t)
	l := ownLog(t, a, 2)
	h := trusted(t, l)
	all := keysOf(t, l)
	var held []heldEntry
	for i := range uint64(2) {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		e.Key = nil
		p, err := l.InclusionProof(i, h.Size())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, heldEntry{pos: int(i), proof: p, entry: e})
	}
	out := make([]Fetched, 2)
	_, err := openAllHeld(context.Background(), out, held, h, func(i uint64) (kololog.EntryKey, error) {
		if i == 1 {
			return nil, errDisk
		}
		return slices.Clone(all[i]), nil
	})
	if !errors.Is(err, errDisk) || out[0].Data == nil {
		t.Fatalf("openAllHeld = %v, entry 0 %+v", err, out[0])
	}
	if !bytes.Equal(out[0].Data, make([]byte, len(out[0].Data))) {
		t.Fatal("an opened value was not cleared after the error")
	}
}

// openAllHeld clears the values it opened when the key source panics, and the panic goes on to the caller.
func TestOpenAllHeldClearsOnPanic(t *testing.T) {
	a := newPeer(t)
	l := ownLog(t, a, 2)
	h := trusted(t, l)
	all := keysOf(t, l)
	var held []heldEntry
	for i := range uint64(2) {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		e.Key = nil
		p, err := l.InclusionProof(i, h.Size())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, heldEntry{pos: int(i), proof: p, entry: e})
	}
	out := make([]Fetched, 2)
	var got any
	func() {
		defer func() { got = recover() }()
		openAllHeld(context.Background(), out, held, h, func(i uint64) (kololog.EntryKey, error) {
			if i == 1 {
				panic("key source panic")
			}
			return slices.Clone(all[i]), nil
		})
	}()
	if got != "key source panic" || out[0].Data == nil {
		t.Fatalf("recovered %v, entry 0 %+v", got, out[0])
	}
	if !bytes.Equal(out[0].Data, make([]byte, len(out[0].Data))) {
		t.Fatal("an opened value was not cleared after the panic")
	}
}

// openAllHeld clears the values it opened when ctx is done, and returns the ctx error.
func TestOpenAllHeldClearsOnContext(t *testing.T) {
	a := newPeer(t)
	l := ownLog(t, a, 1)
	h := trusted(t, l)
	e, err := l.Entry(0)
	if err != nil {
		t.Fatal(err)
	}
	e.Key = nil
	p, err := l.InclusionProof(0, h.Size())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{1, 2, 3}
	out := []Fetched{{Data: data}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := openAllHeld(ctx, out, []heldEntry{{proof: p, entry: e}}, h, func(uint64) (kololog.EntryKey, error) {
		t.Error("a key was asked for after the cancel")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("openAllHeld = %v, %v; want context.Canceled", got, err)
	}
	if !bytes.Equal(data, make([]byte, 3)) {
		t.Fatalf("the value was not cleared: %v", data)
	}
}

// Fetched.Index of an entry reported with an error is its index in the log, whatever the start of the range.
func TestHeldKeyErrorsKeepTheIndex(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 6)
	pinOf(t, pin, alice, l)
	all := keysOf(t, l)
	bp, _ := connect(t, bob, pin, nil)
	got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 2, 5, func(i uint64) (kololog.EntryKey, error) {
		switch i {
		case 3:
			return slices.Clone(all[0]), nil
		case 4:
			return nil, kololog.ErrKeyUnavailable
		}
		return slices.Clone(all[i]), nil
	})
	if err != nil || len(got) != 4 {
		t.Fatalf("FetchWithKeys = %d entries, %v", len(got), err)
	}
	for j, want := range []error{nil, ErrKeyMismatch, kololog.ErrKeyUnavailable, nil} {
		f := got[j]
		if f.Index != 2+uint64(j) || !errors.Is(f.Err, want) || (want != nil) != (f.Data == nil) {
			t.Fatalf("entry %d: index %d, err %v, data %q; want index %d and err %v", 2+j, f.Index, f.Err, f.Data, 2+j, want)
		}
	}
}

// FetchKeys ends its stream, so the pin stops serving it well before its read timeout would.
func TestFetchKeysEndsItsStream(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Keys })
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	if _, err := FetchKeys(testCtx(t), ba, trusted(t, l), 0, 2); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(timeout / 2); a.srv.Stats().ActiveStreams != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("ActiveStreams = %d after FetchKeys returned, want 0", a.srv.Stats().ActiveStreams)
		}
	}
}

// The requests the pin sees are the same bytes whether the caller holds no keys, all of them or some, and
// whatever they are.
func TestTranscriptIndependentOfKeys(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 2)
	bigAppend(t, l, 3)
	appendN(t, l, 3)
	all := keysOf(t, l)
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	last := l.Len() - 1
	r := pinOf(t, pin, alice, l)
	h := trusted(t, l)
	pin.srv = nil
	wrong := func(uint64) (kololog.EntryKey, error) { return bytes.Repeat([]byte{9}, keySize), nil }
	var transcripts [][]byte
	for _, keys := range []func(uint64) (kololog.EntryKey, error){
		nil, held(all, 0), held(all[:3], 0), wrong,
		func(uint64) (kololog.EntryKey, error) { return nil, nil },
	} {
		bp, pb := connect(t, bob, pin, nil)
		done := make(chan []byte, 1)
		rawServe(t, pb, func(st *kolotransport.Stream) {
			var raw []byte
			defer func() { done <- raw }()
			head, _ := r.Head()
			for {
				b, err := readRaw(st)
				if err != nil {
					return
				}
				raw = append(raw, b...)
				m, err := decode(b, true)
				if err != nil {
					t.Error(err)
					return
				}
				resp := message{typ: tHead, head: head.Encode(), header: r.Header().Encode()}
				if m.typ == tFetchReq {
					resp, _ = entries(r, false, m.a, m.b, m.size)
				}
				st.Write(wire(resp))
			}
		})
		var err error
		if keys == nil {
			_, err = Fetch(testCtx(t), bp, h, 0, last)
		} else {
			_, err = FetchWithKeys(testCtx(t), bp, h, 0, last, keys)
		}
		if err != nil {
			t.Fatal(err)
		}
		bp.Close()
		transcripts = append(transcripts, <-done)
	}
	if len(transcripts[0]) == 0 {
		t.Fatal("no request seen")
	}
	for i, got := range transcripts[1:] {
		if !bytes.Equal(got, transcripts[0]) {
			t.Fatalf("the requests of variant %d differ from those of Fetch", i+1)
		}
	}
}

// A held key that does not fit its entry is reported for that entry alone, whatever is wrong with it.
func TestHeldKeyBadShapes(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 3)
	pinOf(t, pin, alice, l)
	all := keysOf(t, l)
	bp, _ := connect(t, bob, pin, nil)
	for name, key := range map[string]kololog.EntryKey{
		"another entry's key": all[0],
		"too short":           make([]byte, keySize/2),
		"too long":            make([]byte, keySize+1),
		"all zero":            make([]byte, keySize),
	} {
		got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 1, 1, func(uint64) (kololog.EntryKey, error) {
			return slices.Clone(key), nil
		})
		if err != nil || len(got) != 1 || !errors.Is(got[0].Err, ErrKeyMismatch) || got[0].Data != nil {
			t.Fatalf("%s: FetchWithKeys = %+v, %v; want ErrKeyMismatch for the entry", name, got, err)
		}
	}
	// An empty key that is not nil holds no key.
	got, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 1, 1, func(uint64) (kololog.EntryKey, error) {
		return kololog.EntryKey{}, nil
	})
	if err != nil || len(got) != 1 || got[0].Err != kololog.ErrKeyUnavailable || got[0].Data != nil {
		t.Fatalf("empty key: FetchWithKeys = %+v, %v", got, err)
	}
}

// A key that comes back with an error is cleared, and the error does not carry it.
func TestHeldKeyWithErrorCleared(t *testing.T) {
	checkGoroutines(t)
	alice, bob, pin := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, alice, 3)
	pinOf(t, pin, alice, l)
	all := keysOf(t, l)
	bp, _ := connect(t, bob, pin, nil)
	var given kololog.EntryKey
	_, err := FetchWithKeys(testCtx(t), bp, trusted(t, l), 1, 1, func(uint64) (kololog.EntryKey, error) {
		given = slices.Clone(all[1])
		return given, errDisk
	})
	if !errors.Is(err, errDisk) || !bytes.Equal(given, make([]byte, keySize)) {
		t.Fatalf("err = %v, key after the call %x", err, given)
	}
	if bytes.Contains([]byte(err.Error()), all[1]) {
		t.Fatal("the key is in the error")
	}
}

// A peer without access to the log, or with Ciphertext access, gives no key through FetchKeys.
func TestFetchKeysAccessLevels(t *testing.T) {
	for _, access := range []Access{NoAccess, Ciphertext} {
		checkGoroutines(t)
		alice, bob := newPeer(t), newPeer(t)
		alice.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return access })
		l := ownLog(t, alice, 3)
		ba, _ := connect(t, bob, alice, nil)
		keys, err := FetchKeys(testCtx(t), ba, trusted(t, l), 0, 2)
		for _, k := range keys {
			if k != nil {
				t.Fatalf("access %d: a key came from the peer", access)
			}
		}
		if access == NoAccess && (!errors.Is(err, ErrNotFound) || keys != nil) {
			t.Fatalf("NoAccess: FetchKeys = %v, %v; want ErrNotFound", keys, err)
		}
		if access == Ciphertext && err != nil {
			t.Fatalf("Ciphertext: FetchKeys = %v", err)
		}
	}
}

// FetchKeys stops with the context and returns no keys.
func TestFetchKeysContext(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	l := ownLog(t, a, 4)
	c.srv = nil
	hh, _ := l.Head()
	bc, cb := connect(t, b, c, nil)
	ctx, cancel := context.WithCancel(testCtx(t))
	rawServe(t, cb, func(st *kolotransport.Stream) {
		readMsg(st, true)
		st.Write(wire(message{typ: tHead, head: hh.Encode(), header: l.Header().Encode()}))
		readMsg(st, true)
		st.Write(wire(message{typ: tState, a: 2, items: []item{{index: 1, key: bytes.Repeat([]byte{5}, keySize)}}}))
		readMsg(st, true)
		cancel()
		readMsg(st, true)
	})
	got, err := FetchKeys(ctx, bc, trusted(t, l), 0, 3)
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("FetchKeys = %v, %v; want context.Canceled", got, err)
	}
}
