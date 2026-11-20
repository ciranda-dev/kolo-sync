package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func trusted(t *testing.T, s Source) kololog.VerifiedHead {
	t.Helper()
	h, err := s.Head()
	if err != nil {
		t.Fatal(err)
	}
	v, err := kololog.VerifyHead(h.LogKey, h.LogID, h)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// getter is a log or replica whose values Fetch results are compared with.
type getter interface {
	Get(uint64) ([]byte, error)
}

// sameValues checks that got holds the values of entries start to end of l, in order.
func sameValues(t *testing.T, got []Fetched, l getter, start, end uint64) {
	t.Helper()
	if uint64(len(got)) != end-start+1 {
		t.Fatalf("%d entries, want %d", len(got), end-start+1)
	}
	for j, f := range got {
		i := start + uint64(j)
		want, err := l.Get(i)
		if err != nil {
			t.Fatal(err)
		}
		if f.Index != i || f.Err != nil || !bytes.Equal(f.Data, want) {
			t.Fatalf("entry %d: index %d, err %v, data %q, want %q", i, f.Index, f.Err, f.Data, want)
		}
	}
}

func TestFetch(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 10)
	ba, _ := connect(t, b, a, nil)
	h, err := FetchHead(testCtx(t), ba, a.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	if h.Size() != 10 || h.Root() != trusted(t, l).Root() {
		t.Fatalf("FetchHead = %v", h)
	}
	for _, r := range [][2]uint64{{0, 0}, {4, 4}, {9, 9}, {2, 7}, {0, 9}} {
		got, err := Fetch(testCtx(t), ba, h, r[0], r[1])
		if err != nil {
			t.Fatalf("Fetch(%d, %d) = %v", r[0], r[1], err)
		}
		sameValues(t, got, l, r[0], r[1])
	}
}

func TestFetchInChunks(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 1)
	bigAppend(t, l, 5) // one a message: an answer is filled to about 1 MiB, and an entry of 1.5 MiB goes alone
	ba, _ := connect(t, b, a, nil)
	st := rawStream(t, ba)
	st.Write(wire(headReq(l.Header().LogKey, l.ID())))
	readMsg(st, false)
	st.Write(wire(message{typ: tFetchReq, a: 1, b: 5, size: 6}))
	if m, err := readMsg(st, false); err != nil || m.typ != tFetch || len(m.entries) != 1 || len(m.proofs) != 1 {
		t.Fatalf("FETCH = type %d, %d entries, %v; want 1 entry", m.typ, len(m.entries), err)
	}
	got, err := Fetch(testCtx(t), ba, trusted(t, l), 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 0, 5)
}

// A client may check entries against an older head it trusts, as long as the peer's history extends it.
func TestFetchOlderTrustedHead(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	h := trusted(t, l)
	appendN(t, l, 4)
	ba, _ := connect(t, b, a, nil)
	got, err := Fetch(testCtx(t), ba, h, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 0, 2)
	if _, err := Fetch(testCtx(t), ba, h, 2, 3); !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, kololog.ErrOutOfRange) {
		t.Fatalf("Fetch past the trusted head = %v, want ErrInvalidArgument and kololog.ErrOutOfRange", err)
	}
}

func TestFetchInvalidArguments(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	h := trusted(t, l)
	ctx := testCtx(t)
	for name, err := range map[string]error{
		"nil conn":       second(Fetch(ctx, nil, h, 0, 0)),
		"zero head":      second(Fetch(ctx, ba, kololog.VerifiedHead{}, 0, 0)),
		"past the head":  second(Fetch(ctx, ba, h, 0, 3)),
		"start past end": second(Fetch(ctx, ba, h, 2, 1)),
		"huge end":       second(Fetch(ctx, ba, h, 0, 1<<63)),
	} {
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", name, err)
		}
	}
	for name, err := range map[string]error{
		"nil conn":  second(FetchHead(ctx, nil, a.id.PublicKey(), l.ID())),
		"nil owner": second(FetchHead(ctx, ba, nil, l.ID())),
		"short key": second(FetchHead(ctx, ba, a.id.PublicKey()[:31], l.ID())),
	} {
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("FetchHead %s: %v, want ErrInvalidArgument", name, err)
		}
	}
}

func second[T any](_ T, err error) error { return err }

// A log is named by owner and ID: the right ID under another owner is a log the server does not have.
func TestFetchHeadWrongOwner(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 1)
	ba, _ := connect(t, b, a, nil)
	if _, err := FetchHead(testCtx(t), ba, b.id.PublicKey(), l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FetchHead = %v, want ErrNotFound", err)
	}
	if _, err := FetchHeader(testCtx(t), ba, b.id.PublicKey(), l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FetchHeader = %v, want ErrNotFound", err)
	}
}

func TestFetchDeleted(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 4)
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	ba, _ := connect(t, b, a, nil)
	got, err := Fetch(testCtx(t), ba, trusted(t, l), 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if f := got[1]; f.Index != 1 || f.Data != nil || !errors.Is(f.Err, kololog.ErrDeleted) {
		t.Fatalf("deleted entry: %+v, want kololog.ErrDeleted", f)
	}
	sameValues(t, got[2:], l, 2, 3)
	sameValues(t, got[:1], l, 0, 0)
}

func TestFetchKeysOnlyWhenAuthorized(t *testing.T) {
	for _, access := range []Access{Ciphertext, Keys} {
		t.Run(fmt.Sprint(access), func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return access })
			l := ownLog(t, a, 3)
			ba, _ := connect(t, b, a, nil)
			got, err := Fetch(testCtx(t), ba, trusted(t, l), 0, 2)
			if err != nil {
				t.Fatal(err)
			}
			if access == Keys {
				sameValues(t, got, l, 0, 2)
			} else {
				for _, f := range got {
					if f.Data != nil || !errors.Is(f.Err, kololog.ErrKeyUnavailable) {
						t.Fatalf("entry %d without Keys: %+v, want kololog.ErrKeyUnavailable", f.Index, f)
					}
				}
			}
			// On the wire: a key comes only with Keys access.
			st := rawStream(t, ba)
			st.Write(wire(headReq(l.Header().LogKey, l.ID())))
			readMsg(st, false)
			st.Write(wire(message{typ: tFetchReq, a: 0, b: 2, size: 3}))
			m, err := readMsg(st, false)
			if err != nil || m.typ != tFetch || len(m.entries) != 3 {
				t.Fatalf("FETCH = type %d, %d entries, %v", m.typ, len(m.entries), err)
			}
			for i, e := range m.entries {
				if (len(e.Key) != 0) != (access == Keys) {
					t.Fatalf("entry %d with %v access: key sent %v", i, access, len(e.Key) != 0)
				}
			}
			wipe(m)
		})
	}
}

func TestFetchTamperedEntry(t *testing.T) {
	for name, change := range map[string]func(*kololog.Entry){
		"ciphertext": func(e *kololog.Entry) { e.Ciphertext[len(e.Ciphertext)-1] ^= 1 },
		"record":     func(e *kololog.Entry) { e.Record[len(e.Record)-1] ^= 1 },
		"key":        func(e *kololog.Entry) { e.Key[0] ^= 1 },
		"no ciphertext": func(e *kololog.Entry) {
			e.Ciphertext = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			l := ownLog(t, a, 4)
			a.srv.Offer(tamper{Source: l, entry: func(i uint64, e *kololog.Entry) {
				if i == 2 {
					change(e)
				}
			}})
			ba, _ := connect(t, b, a, nil)
			if _, err := Fetch(testCtx(t), ba, trusted(t, l), 0, 3); !errors.Is(err, ErrInvalid) || !errors.Is(err, kololog.ErrBadEntry) {
				t.Fatalf("Fetch = %v, want ErrInvalid wrapping kololog.ErrBadEntry", err)
			}
		})
	}
}

// shifted serves entry i+1, with its own valid proof, when asked for entry i.
type shifted struct{ Source }

func (s shifted) Record(i uint64) (kololog.Record, error) { return s.Source.Record(i + 1) }
func (s shifted) Entry(i uint64) (kololog.Entry, error)   { return s.Source.Entry(i + 1) }
func (s shifted) InclusionProof(i, size uint64) (kololog.InclusionProof, error) {
	return s.Source.InclusionProof(i+1, size)
}

// earlier serves entry i-1, with its own valid proof, when asked for entry i.
type earlier struct{ Source }

func (s earlier) Record(i uint64) (kololog.Record, error) { return s.Source.Record(i - 1) }
func (s earlier) Entry(i uint64) (kololog.Entry, error)   { return s.Source.Entry(i - 1) }
func (s earlier) InclusionProof(i, size uint64) (kololog.InclusionProof, error) {
	return s.Source.InclusionProof(i-1, size)
}

func TestFetchTamperedProof(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(Source) Source
		want   error
	}{
		"path hash": {func(s Source) Source {
			return tamper{Source: s, incl: func(p *kololog.InclusionProof) { p.Path[0][0] ^= 1 }}
		}, kololog.ErrBadProof},
		"path cut": {func(s Source) Source {
			return tamper{Source: s, incl: func(p *kololog.InclusionProof) { p.Path = p.Path[1:] }}
		}, kololog.ErrBadProof},
		"tree size": {func(s Source) Source {
			return tamper{Source: s, incl: func(p *kololog.InclusionProof) { p.Size-- }}
		}, kololog.ErrBadProof},
		"a later entry with its proof":    {func(s Source) Source { return shifted{s} }, nil},
		"an earlier entry with its proof": {func(s Source) Source { return earlier{s} }, nil},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			l := ownLog(t, a, 6)
			a.srv.Offer(tc.change(l))
			ba, _ := connect(t, b, a, nil)
			_, err := Fetch(testCtx(t), ba, trusted(t, l), 1, 3)
			if !errors.Is(err, ErrInvalid) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("Fetch = %v, want ErrInvalid wrapping %v", err, tc.want)
			}
		})
	}
}

func TestFetchTamperedHead(t *testing.T) {
	for name, change := range map[string]func(*kololog.Head){
		"signature": func(h *kololog.Head) { h.Signature[0] ^= 1 },
		"root":      func(h *kololog.Head) { h.Root[0] ^= 1 },
		"log ID":    func(h *kololog.Head) { h.LogID[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			l := ownLog(t, a, 3)
			a.srv.Offer(tamper{Source: l, head: change})
			ba, _ := connect(t, b, a, nil)
			if _, err := Fetch(testCtx(t), ba, trusted(t, l), 0, 2); !errors.Is(err, ErrInvalid) || !errors.Is(err, kololog.ErrInvalidHead) {
				t.Fatalf("Fetch = %v, want ErrInvalid wrapping kololog.ErrInvalidHead", err)
			}
			if _, err := FetchHead(testCtx(t), ba, a.id.PublicKey(), l.ID()); !errors.Is(err, ErrInvalid) {
				t.Fatalf("FetchHead = %v, want ErrInvalid", err)
			}
		})
	}
}

// edgeSource has one entry whose ciphertext takes all the room a FETCH answer has left, plus extra bytes.
type edgeSource struct {
	Source
	extra int
	reads *int
}

var edgeProof = kololog.InclusionProof{Index: 0, Size: 1, Path: make([][kololog.HashSize]byte, 8)}

func (s edgeSource) room() int {
	// Every size near 4 MiB takes a 4-byte uvarint in the record.
	return MaxMessageSize - overhead - len(kololog.Record{Size: 1 << 21}.Encode()) - len(edgeProof.Encode())
}

func (s edgeSource) Record(uint64) (kololog.Record, error) {
	return kololog.Record{Size: uint64(s.room() + s.extra)}, nil
}

func (s edgeSource) InclusionProof(uint64, uint64) (kololog.InclusionProof, error) {
	return edgeProof, nil
}

func (s edgeSource) Entry(uint64) (kololog.Entry, error) {
	*s.reads++
	return kololog.Entry{Record: kololog.Record{}.Encode(), Ciphertext: make([]byte, s.room()+s.extra)}, nil
}

// The proof counts toward the answer's size: before the entry is read, and once its framing is known.
func TestFetchAnswerCountsTheProof(t *testing.T) {
	for _, tc := range []struct {
		extra, reads int
	}{{1, 0}, {0, 1}} {
		reads := 0
		_, code := entries(edgeSource{extra: tc.extra, reads: &reads}, false, 0, 0, 1)
		if code != codeTooLarge || reads != tc.reads {
			t.Fatalf("extra %d: code %d after %d reads, want codeTooLarge after %d", tc.extra, code, reads, tc.reads)
		}
	}
}

func TestFetchPeerBehindOrForked(t *testing.T) {
	for name, tc := range map[string]struct {
		nb   int // entries the peer's copy adds to the 3 shared ones; -1 serves the shared prefix
		want []error
	}{
		"older head":            {-1, []error{ErrBehind}},
		"fork of the same size": {2, []error{ErrDiverged}},
		"longer fork":           {4, []error{ErrInvalid, kololog.ErrBadProof}},
		"shorter fork":          {1, []error{ErrBehind}},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			base, ra, rb := forks(t, a.id, 3, 2, max(tc.nb, 0))
			if tc.nb < 0 {
				rb = base
			}
			a.srv.Offer(rb)
			ba, _ := connect(t, b, a, nil)
			// Entry 0 is in both histories, yet only a proof in the trusted tree counts.
			for _, r := range [][2]uint64{{0, 0}, {3, 4}} {
				_, err := Fetch(testCtx(t), ba, trusted(t, ra), r[0], r[1])
				for _, want := range tc.want {
					if !errors.Is(err, want) {
						t.Fatalf("Fetch(%d, %d) = %v, want %v", r[0], r[1], err, tc.want)
					}
				}
			}
		})
	}
}

func TestFetchNotFoundLooksTheSame(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	var denied kololog.LogID
	a.srv = NewServer(func(_, _ ed25519.PublicKey, id kololog.LogID) Access {
		if id == denied {
			return NoAccess
		}
		return Keys
	})
	dl := ownLog(t, a, 2)
	denied = dl.ID()
	held, err := a.st.Create(a.id)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	appendN(t, held, 2)
	ba, _ := connect(t, b, a, nil)
	for name, l := range map[string]Source{"unauthorized": dl, "not offered": held} {
		if _, err := Fetch(testCtx(t), ba, trusted(t, l), 0, 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: Fetch = %v, want ErrNotFound", name, err)
		}
		if _, err := FetchHead(testCtx(t), ba, a.id.PublicKey(), l.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: FetchHead = %v, want ErrNotFound", name, err)
		}
	}

	// Withdrawn after the stream started: the next FETCH_REQ gets the answer of a missing log.
	l := ownLog(t, a, 2)
	st := rawStream(t, ba)
	st.Write(wire(headReq(l.Header().LogKey, l.ID())))
	readMsg(st, false)
	a.srv.Withdraw(l.Header().LogKey, l.ID())
	st.Write(wire(message{typ: tFetchReq, a: 0, b: 1, size: 2}))
	if got, want := readAll(t, st), wire(message{typ: tError, code: codeNotFound}); !bytes.Equal(got, want) {
		t.Fatalf("answer %x, want %x", got, want)
	}
}

func TestServerRejectsBadFetchRanges(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	for _, req := range []message{
		{typ: tFetchReq, a: 2, b: 1, size: 3},
		{typ: tFetchReq, a: 0, b: 2, size: 2},
		{typ: tFetchReq, a: 0, b: 3, size: 3},
		{typ: tFetchReq, a: 0, b: 0, size: 0},
		{typ: tFetchReq, a: 0, b: 0, size: 4},
		{typ: tFetchReq, a: 1 << 62, b: 1 << 63, size: 1<<64 - 1},
	} {
		st := rawStream(t, ba)
		st.Write(wire(headReq(l.Header().LogKey, l.ID())))
		readMsg(st, false)
		st.Write(wire(req))
		if got, want := readAll(t, st), wire(message{typ: tError, code: codeProtocol}); !bytes.Equal(got, want) {
			t.Fatalf("request %+v: answer %x, want %x", req, got, want)
		}
	}
}

func TestFetchClientRejectsBadAnswers(t *testing.T) {
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	h := trusted(t, l)
	hh, _ := l.Head()
	e0, _ := l.Entry(0)
	e1, _ := l.Entry(1)
	p0, _ := l.InclusionProof(0, 3)
	p1, _ := l.InclusionProof(1, 3)
	for name, tc := range map[string]struct {
		resp message
		want error
	}{
		"no entries":      {message{typ: tFetch}, ErrProtocol},
		"too many":        {message{typ: tFetch, entries: []kololog.Entry{e0, e1}, proofs: [][]byte{p0.Encode(), p1.Encode()}}, ErrProtocol},
		"entries type":    {message{typ: tEntries, entries: []kololog.Entry{e0}}, ErrProtocol},
		"bad proof bytes": {message{typ: tFetch, entries: []kololog.Entry{e0}, proofs: [][]byte{{1}}}, kololog.ErrMalformed},
		"proof of 1":      {message{typ: tFetch, entries: []kololog.Entry{e0}, proofs: [][]byte{p1.Encode()}}, ErrInvalid},
		"entry 1":         {message{typ: tFetch, entries: []kololog.Entry{e1}, proofs: [][]byte{p1.Encode()}}, ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			c := newPeer(t)
			c.srv = nil
			bc, cb := connect(t, b, c, nil)
			// The server repeats its answer to every request; the client must stop at the first.
			asked := make(chan int, 1)
			rawServe(t, cb, func(st *kolotransport.Stream) {
				readMsg(st, true)
				st.Write(wire(message{typ: tHead, head: hh.Encode(), header: l.Header().Encode()}))
				n := 0
				for ; n < 5; n++ {
					if _, err := readMsg(st, true); err != nil {
						break
					}
					st.Write(wire(tc.resp))
				}
				asked <- n
			})
			if _, err := Fetch(testCtx(t), bc, h, 0, 0); !errors.Is(err, tc.want) {
				t.Fatalf("Fetch = %v, want %v", err, tc.want)
			}
			if n := <-asked; n != 1 {
				t.Fatalf("the client sent %d requests after a bad answer, want 1", n)
			}
		})
	}
}

// The largest entry ENTRIES carries also fits in FETCH, with its proof; one byte more fits in neither.
func TestFetchLargestEntry(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 1)
	const largest = 63<<16 - 4 // pads to 63 × 64 KiB; one byte more pads to 4 MiB
	if _, err := l.Append(make([]byte, largest)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(make([]byte, largest+1)); err != nil {
		t.Fatal(err)
	}
	// It fits with the longest proof any tree has, 64 hashes.
	e, err := l.Entry(1)
	if err != nil {
		t.Fatal(err)
	}
	clear(e.Key)
	longest := kololog.InclusionProof{Index: 1<<64 - 2, Size: 1<<64 - 1, Path: make([][kololog.HashSize]byte, 64)}
	if n := overhead + entrySize(e) + blen(longest.Encode()); n > MaxMessageSize {
		t.Fatalf("the largest entry and proof take %d bytes", n)
	}
	ba, _ := connect(t, b, a, nil)
	h := trusted(t, l)
	got, err := Fetch(testCtx(t), ba, h, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 1, 1)
	if _, err := Fetch(testCtx(t), ba, h, 2, 2); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch of a larger entry = %v, want ErrTooLarge", err)
	}
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(testCtx(t), ba, r); !errors.Is(err, ErrTooLarge) || r.Len() != 2 {
		t.Fatalf("Pull = %v with %d entries, want ErrTooLarge after 2", err, r.Len())
	}
}

func TestFetchOversizedEntryIsNeverRead(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 1)
	if _, err := l.Append(make([]byte, MaxMessageSize)); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 1)
	src := &counting{Source: l, reads: make(map[uint64]int)}
	a.srv.Offer(src)
	ba, _ := connect(t, b, a, nil)
	h := trusted(t, l)
	for _, r := range [][2]uint64{{0, 2}, {1, 1}, {1, 2}} {
		if _, err := Fetch(testCtx(t), ba, h, r[0], r[1]); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Fetch(%d, %d) = %v, want ErrTooLarge", r[0], r[1], err)
		}
	}
	got, err := Fetch(testCtx(t), ba, h, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	sameValues(t, got, l, 2, 2)
	src.mu.Lock()
	defer src.mu.Unlock()
	if n := src.reads[1]; n != 0 {
		t.Fatalf("the large entry was read %d times", n)
	}
}

func TestFetchConcurrent(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 40)
	ba, _ := connect(t, b, a, nil)
	h := trusted(t, l)
	var wg sync.WaitGroup
	for i := range uint64(MaxStreams) {
		wg.Go(func() {
			got, err := Fetch(testCtx(t), ba, h, i, i+20)
			if err != nil {
				t.Error(err)
				return
			}
			for j, f := range got {
				if want, _ := l.Get(i + uint64(j)); !bytes.Equal(f.Data, want) || f.Err != nil {
					t.Errorf("Fetch from %d: entry %d differs", i, j)
				}
			}
		})
	}
	wg.Wait()
	waitIdle(t, a.srv)
}

func TestFetchServerStats(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 4)
	ba, _ := connect(t, b, a, nil)
	st := rawStream(t, ba)
	var want uint64
	for _, req := range []message{headReq(l.Header().LogKey, l.ID()), {typ: tFetchReq, a: 1, b: 3, size: 4}} {
		st.Write(wire(req))
		m, err := readMsg(st, false)
		if err != nil {
			t.Fatal(err)
		}
		want += uint64(len(wire(m)))
		wipe(m)
	}
	// The server counts an answer just after writing it, so the client may read it first.
	for deadline := time.Now().Add(5 * time.Second); a.srv.Stats().BytesSent != want && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if s := a.srv.Stats(); s.BytesSent != want || s.ActiveStreams != 1 {
		t.Fatalf("Stats = %+v, want %d bytes and 1 stream", s, want)
	}
	end(st)
	waitIdle(t, a.srv)
	before := a.srv.Stats().BytesSent
	if _, err := Fetch(testCtx(t), ba, trusted(t, l), 1, 3); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, a.srv)
	if sent := a.srv.Stats().BytesSent - before; sent != want {
		t.Fatalf("Fetch made the server send %d bytes, want %d", sent, want)
	}
}

// failing serves src, but one of its reads fails.
type failing struct {
	Source
	what string
}

var errDisk = errors.New("disk error")

func (s failing) Record(i uint64) (kololog.Record, error) {
	if s.what == "record" {
		return kololog.Record{}, errDisk
	}
	return s.Source.Record(i)
}

func (s failing) Entry(i uint64) (kololog.Entry, error) {
	if s.what == "entry" {
		return kololog.Entry{}, errDisk
	}
	return s.Source.Entry(i)
}

func (s failing) InclusionProof(i, size uint64) (kololog.InclusionProof, error) {
	if s.what == "proof" {
		return kololog.InclusionProof{}, errDisk
	}
	return s.Source.InclusionProof(i, size)
}

func TestFetchSourceError(t *testing.T) {
	for _, what := range []string{"record", "entry", "proof"} {
		t.Run(what, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			l := ownLog(t, a, 2)
			a.srv.Offer(failing{Source: l, what: what})
			ba, _ := connect(t, b, a, nil)
			if _, err := Fetch(testCtx(t), ba, trusted(t, l), 0, 1); !errors.Is(err, ErrBusy) {
				t.Fatalf("Fetch = %v, want ErrBusy", err)
			}
		})
	}
}

func TestFetchContext(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	l := ownLog(t, b, 2)
	ba, ab := connect(t, b, a, nil)
	ctx, cancel := context.WithCancel(testCtx(t))
	rawServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		cancel()
		readMsg(st, true)
	})
	if _, err := Fetch(ctx, ba, trusted(t, l), 0, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Fetch = %v, want context.Canceled", err)
	}
}

func TestFetchTimeout(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	l := ownLog(t, b, 2)
	hh, _ := l.Head()
	ba, ab := connect(t, b, a, nil)
	rawServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		st.Write(wire(message{typ: tHead, head: hh.Encode(), header: l.Header().Encode()}))
		readMsg(st, true)
		readMsg(st, true) // silent until the client gives up
	})
	if _, err := Fetch(testCtx(t), ba, trusted(t, l), 0, 1); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Fetch = %v, want ErrTimeout", err)
	}
}

// serveCancel answers the HEAD request, then, if answered, the first FETCH request with two entries, and
// cancels on the next request; if not, it cancels on the first.
func serveCancel(t *testing.T, ab *kolosecure.Conn, l Source, answered bool, cancel func()) {
	t.Helper()
	hh, _ := l.Head()
	rawServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		st.Write(wire(message{typ: tHead, head: hh.Encode(), header: l.Header().Encode()}))
		req, _ := readMsg(st, true)
		if answered {
			m, _ := entries(l, true, req.a, req.b, req.size)
			m.entries, m.proofs = m.entries[:2], m.proofs[:2]
			st.Write(wire(m))
			readMsg(st, true)
		}
		cancel()
		readMsg(st, true)
	})
}

// A cancel returns ctx.Err(), not the stream error that follows it, whether it comes before the first
// answer or after an answer has already delivered entries.
func TestFetchContextMidStream(t *testing.T) {
	for name, keys := range map[string]func(uint64) (kololog.EntryKey, error){
		"Fetch":         nil,
		"FetchWithKeys": func(uint64) (kololog.EntryKey, error) { return nil, nil },
	} {
		for _, answered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/answered=%v", name, answered), func(t *testing.T) {
				checkGoroutines(t)
				a, b := newPeer(t), newPeer(t)
				a.srv = nil
				l := ownLog(t, b, 4)
				ba, ab := connect(t, b, a, nil)
				ctx, cancel := context.WithCancel(testCtx(t))
				serveCancel(t, ab, l, answered, cancel)
				var got []Fetched
				var err error
				if keys == nil {
					got, err = Fetch(ctx, ba, trusted(t, l), 0, 3)
				} else {
					got, err = FetchWithKeys(ctx, ba, trusted(t, l), 0, 3, keys)
				}
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("%s = %v, want context.Canceled", name, err)
				}
				if got != nil {
					t.Fatalf("%s returned %d entries with the error", name, len(got))
				}
			})
		}
	}
}

// The values of an answer that arrived before a cancel are cleared.
func TestFetchRangeClearsOnContext(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	l := ownLog(t, b, 4)
	ba, ab := connect(t, b, a, nil)
	ctx, cancel := context.WithCancel(testCtx(t))
	serveCancel(t, ab, l, true, cancel)
	cl, ph, _, err := open(ctx, ba, b.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.close()
	out, _, err := cl.fetchRange(trusted(t, l), ph, 0, 3, false)
	if err == nil {
		t.Fatal("fetchRange returned no error after the cancel")
	}
	if len(out) != 2 || len(out[0].Data) == 0 {
		t.Fatalf("fetchRange returned %d entries, want the 2 of the first answer", len(out))
	}
	for i, f := range out {
		if !bytes.Equal(f.Data, make([]byte, len(f.Data))) {
			t.Fatalf("value %d not cleared after %v", i, err)
		}
	}
}
