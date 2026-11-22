package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// streamTrace is what a scripted streaming server read and sent.
type streamTrace struct {
	mu        sync.Mutex
	reqs      []message
	ends      []uint64 // the end index of each ENTRIES answer sent, in order
	maxCredit int64    // the most credit the server held after it read a request
}

func (tr *streamTrace) requests(typ uint64) (out []message) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, m := range tr.reqs {
		if m.typ == typ {
			out = append(out, m)
		}
	}
	return out
}

func (tr *streamTrace) ending() []uint64 {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]uint64(nil), tr.ends...)
}

// streamFn may send message n (from 0) of kind 'E', an ENTRIES answer, or 'P', the proof after it, itself, by returning
// true; real is the true message.
type streamFn func(st *kolotransport.Stream, kind byte, n int, real []byte) bool

// serveStreamScript answers the next stream of conn like a Server that offers src and gives every peer Keys, and records what it
// reads and sends. A STREAM_REQ and the CREDIT_REQs after it are served as feed says; the other requests one by one.
func serveStreamScript(t *testing.T, conn *kolosecure.Conn, src Source, fn streamFn) *streamTrace {
	t.Helper()
	tr := new(streamTrace)
	acceptServe(t, conn, func(st *kolotransport.Stream) {
		if _, err := readMsg(st, true); err != nil {
			return
		}
		h, _ := src.Head()
		if _, err := writeMsg(st, message{typ: tHead, head: h.Encode(), header: src.Header().Encode()}); err != nil {
			return
		}
		st.SetWriteDeadline(time.Time{})
		var f feed
		sent := 0
		send := func(kind byte, real []byte) bool {
			if fn != nil && fn(st, kind, sent, real) {
				return true
			}
			_, err := st.Write(real)
			return err == nil
		}
		for {
			req, err := readMsg(st, true)
			if err != nil {
				return
			}
			tr.mu.Lock()
			tr.reqs = append(tr.reqs, req)
			tr.mu.Unlock()
			var resp message
			code := uint64(0)
			switch req.typ {
			case tStreamReq, tCreditReq:
				if code = f.apply(req, h.Size); code != 0 {
					break
				}
				tr.mu.Lock()
				tr.maxCredit = max(tr.maxCredit, f.credit)
				tr.mu.Unlock()
				for f.credit > 0 && f.next < f.size {
					resp, code = entries(src, f.keys, f.next, f.size-1, 0)
					if code != 0 {
						break
					}
					real := wire(resp)
					ok := send('E', real)
					f.credit -= int64(len(real) - 4)
					f.next += uint64(len(resp.entries))
					tr.mu.Lock()
					tr.ends = append(tr.ends, f.next)
					tr.mu.Unlock()
					if !ok {
						return
					}
					if f.next < f.size {
						pr, _ := proof(src, f.next, f.size)
						if !send('P', wire(pr)) {
							return
						}
					}
					sent++
				}
				if code == 0 {
					continue
				}
			case tProofReq:
				resp, code = proof(src, req.a, req.b)
			case tEntriesReq:
				resp, code = entries(src, req.keys, req.a, req.b, 0)
			case tStateReq:
				resp, code = state(src, req.keys, req.a, req.b)
			default:
				code = codeProtocol
			}
			if code != 0 {
				resp = message{typ: tError, code: code}
			}
			if _, err := st.Write(wire(resp)); err != nil {
				return
			}
		}
	})
	return tr
}

// streamPull pulls the log l, which a offers, into a new replica of b, with a streaming script in between.
func streamScenario(t *testing.T, sizes []int, fn streamFn) (*peer, *peer, *kolostore.Log, *kolostore.Replica, *kolosecure.Conn, *streamTrace) {
	t.Helper()
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := sizedLog(t, a, sizes)
	a.srv.Offer(l)
	r := openReplica(t, b, l)
	bc, cb := connect(t, b, c, nil)
	tr := serveStreamScript(t, cb, l, fn)
	return a, b, l, r, bc, tr
}

func resume(t *testing.T, a, b *peer, l *kolostore.Log, r *kolostore.Replica) {
	t.Helper()
	ba, _ := connect(t, b, a, nil)
	if err := Pull(testCtx(t), ba, r); err != nil {
		t.Fatalf("resume: %v", err)
	}
	sameLog(t, r, l)
}

// sameLog is sameEntries for logs that may hold deleted entries, which only have to be deleted in both.
func sameLog(t *testing.T, r *kolostore.Replica, want *kolostore.Log) {
	t.Helper()
	if r.Len() != want.Len() {
		t.Fatalf("Len %d, want %d", r.Len(), want.Len())
	}
	for i := range want.Len() {
		a, errA := r.Get(i)
		b, errB := want.Get(i)
		if errors.Is(errB, kololog.ErrDeleted) {
			if !errors.Is(errA, kololog.ErrDeleted) {
				t.Fatalf("entry %d is not deleted: %v", i, errA)
			}
			continue
		}
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			t.Fatalf("entry %d differs: %v %v", i, errA, errB)
		}
	}
}

func TestStreamPullsTheSameLog(t *testing.T) {
	for depth := 0; depth <= MaxInFlight; depth++ {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			checkGoroutines(t)
			a := newPeer(t)
			b, _ := slowPeer(t, 2*time.Millisecond)
			l := sizedLog(t, a, mixedSizes(60))
			a.srv.Offer(l)
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			var meter PullMeter
			res, err := PullWith(testCtx(t), ba, r, &PullOptions{InFlight: depth, Meter: &meter})
			if err != nil {
				t.Fatal(err)
			}
			sameEntries(t, r, l)
			if res.KeysFrom != l.Len() {
				t.Fatalf("KeysFrom %d, want %d", res.KeysFrom, l.Len())
			}
			s := res.Stats
			if !s.Streamed || s.Entries != l.Len() || s.Answers == 0 || s.Bytes == 0 || s.Requests == 0 {
				t.Fatalf("stats %+v: want a streamed pull of %d entries", s, l.Len())
			}
			if most := cmpOr(depth, MaxInFlight); s.InFlightMax < 1 || s.InFlightMax > most {
				t.Fatalf("InFlightMax %d, want 1 to %d", s.InFlightMax, most)
			}
			if got := meter.Stats(); got != s {
				t.Fatalf("meter %+v, result %+v", got, s)
			}
			// A pull that is up to date asks for no entries.
			if res, err := PullWith(testCtx(t), ba, r, &PullOptions{Meter: &meter}); err != nil || res.Stats.Requests != 0 {
				t.Fatalf("up to date: %v, %d requests", err, res.Stats.Requests)
			}
		})
	}
}

func cmpOr(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

// A streamed pull sends one STREAM_REQ and then only CREDIT_REQs: no ENTRIES_REQ and no PROOF_REQ for the answers, and it
// never holds more credit at the peer than InFlight requests of it.
func TestStreamAsksOnceAndStaysWithinInFlight(t *testing.T) {
	for _, depth := range []int{1, 2, 3, MaxInFlight} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			checkGoroutines(t)
			a, b, l, r, bc, tr := streamScenario(t, mixedSizes(40), nil)
			_ = a
			res, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: depth})
			if err != nil {
				t.Fatal(err)
			}
			sameEntries(t, r, l)
			_ = b
			if n := len(tr.requests(tStreamReq)); n != 1 {
				t.Fatalf("%d STREAM_REQs, want 1", n)
			}
			if n := len(tr.requests(tEntriesReq)) + len(tr.requests(tProofReq)); n != 0 {
				t.Fatalf("%d ENTRIES_REQs and PROOF_REQs, want none", n)
			}
			first := tr.requests(tStreamReq)[0]
			if first.a != 0 || first.size != l.Len() || !first.keys || first.credit != requestCredit {
				t.Fatalf("STREAM_REQ %+v", first)
			}
			if tr.maxCredit > int64(depth*requestCredit) {
				t.Fatalf("the peer held %d bytes of credit, over %d requests of %d", tr.maxCredit, depth, requestCredit)
			}
			if res.Stats.InFlightMax > depth {
				t.Fatalf("InFlightMax %d over %d", res.Stats.InFlightMax, depth)
			}
		})
	}
}

// With one request in flight the pull asks again only after the credit of the one before is used up.
func TestStreamInFlightOneIsSerial(t *testing.T) {
	checkGoroutines(t)
	_, _, l, r, bc, tr := streamScenario(t, mixedSizes(30), nil)
	if _, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 1}); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
	if tr.maxCredit > requestCredit {
		t.Fatalf("credit %d at the peer, want at most one request of %d", tr.maxCredit, requestCredit)
	}
}

// PullCiphertext and a peer that gives no keys: the entries come without keys and the pull stores them.
func TestStreamCiphertext(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Ciphertext })
	l := sizedLog(t, a, mixedSizes(20))
	a.srv.Offer(l)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	var meter PullMeter
	if _, err := PullWith(testCtx(t), ba, r, &PullOptions{Meter: &meter}); err != nil {
		t.Fatal(err)
	}
	if !meter.Stats().Streamed || r.Len() != l.Len() {
		t.Fatalf("streamed %v, %d of %d entries", meter.Stats().Streamed, r.Len(), l.Len())
	}
	if err := PullCiphertext(testCtx(t), ba, r); err != nil {
		t.Fatal(err)
	}
}

// A cut stream leaves the answers that arrived whole with their proofs, and a later pull ends with the same log.
func TestStreamCutThenResume(t *testing.T) {
	for _, depth := range []int{1, 3, MaxInFlight} {
		for cut := 1; cut <= 4; cut++ {
			t.Run(fmt.Sprintf("depth %d cut %d", depth, cut), func(t *testing.T) {
				checkGoroutines(t)
				a, b, l, r, bc, tr := streamScenario(t, mixedSizes(30), func(st *kolotransport.Stream, kind byte, n int, _ []byte) bool {
					if kind == 'E' && n == cut {
						st.Close()
						st.CancelRead(0)
						return true
					}
					return false
				})
				if _, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: depth}); err == nil {
					t.Fatal("Pull succeeded on a cut stream")
				}
				ends := tr.ending()
				if len(ends) <= cut {
					t.Fatalf("the server sent %d answers", len(ends))
				}
				if r.Len() != ends[cut-1] {
					t.Fatalf("Len %d after the cut, want %d, the end of answer %d", r.Len(), ends[cut-1], cut)
				}
				if _, err := r.Head(); !errors.Is(err, kololog.ErrNoHead) {
					t.Fatalf("Head %v: a partial pull has no head", err)
				}
				resume(t, a, b, l, r)
			})
		}
	}
}

// replaceAt makes a script that sends raw instead of the message of kind and number n.
func replaceAt(kind byte, n int, raw func(real []byte) []byte) streamFn {
	return func(st *kolotransport.Stream, k byte, i int, real []byte) bool {
		if k != kind || i != n {
			return false
		}
		st.Write(raw(real))
		return true
	}
}

// Whatever a peer sends in the place of answer k or its proof, the pull stores the answers before it, whole, and no more,
// ends with the error that says what is wrong, has no head, and a pull from an honest peer then ends with the right log.
func TestStreamHostileAnswers(t *testing.T) {
	const k = 2 // the third answer
	tooMany := func([]byte) []byte {
		m := message{typ: tEntries}
		for range 41 { // the log holds 40
			m.entries = append(m.entries, kololog.Entry{Record: make([]byte, minSigned)})
		}
		return wire(m)
	}
	for _, tc := range []struct {
		name string
		fn   streamFn
		want error
	}{
		{"oversized frame", replaceAt('E', k, func([]byte) []byte { return frame(MaxMessageSize+1, nil) }), ErrTooLarge},
		{"oversized proof", replaceAt('P', k, func([]byte) []byte { return frame(MaxMessageSize+1, nil) }), ErrTooLarge},
		{"garbage", replaceAt('E', k, func([]byte) []byte { return frame(20, make([]byte, 20)) }), ErrProtocol},
		{"empty frame", replaceAt('E', k, func([]byte) []byte { return frame(0, nil) }), ErrProtocol},
		{"a proof for entries", replaceAt('E', k, func([]byte) []byte { return wire(message{typ: tProof, proof: []byte{1}}) }), ErrProtocol},
		{"entries for a proof", replaceAt('P', k, func([]byte) []byte {
			return wire(message{typ: tEntries, entries: []kololog.Entry{{Record: make([]byte, minSigned)}}})
		}), ErrProtocol},
		{"refusal", replaceAt('E', k, func([]byte) []byte { return wire(message{typ: tError, code: codeBusy}) }), ErrBusy},
		{"refused proof", replaceAt('P', k, func([]byte) []byte { return wire(message{typ: tError, code: codeBusy}) }), ErrBusy},
		{"count the body does not hold", replaceAt('E', k, func(real []byte) []byte {
			b := append([]byte(nil), real[4:]...)
			b[2] += 2
			return frame(uint32(len(b)), b)
		}), ErrProtocol},
		{"no entries", replaceAt('E', k, func([]byte) []byte { return wire(message{typ: tEntries}) }), ErrProtocol},
		{"more entries than asked", replaceAt('E', k, tooMany), ErrProtocol},
		{"proof that does not decode", replaceAt('P', k, func([]byte) []byte { return wire(message{typ: tProof, proof: []byte{1, 2, 3}}) }), ErrInvalid},
		{"missing proof", replaceAt('P', k, func([]byte) []byte { return nil }), ErrProtocol},
		{"the answer before again", func() streamFn {
			var before []byte
			return func(st *kolotransport.Stream, kind byte, n int, real []byte) bool {
				if kind != 'E' {
					return false
				}
				if n == k-1 {
					before = real
				}
				if n == k {
					st.Write(before)
					return true
				}
				return false
			}
		}(), ErrInvalid},
		{"truncated body", func(st *kolotransport.Stream, kind byte, n int, real []byte) bool {
			if kind == 'E' && n == k {
				st.Write(real[:len(real)/2])
				st.Close()
				st.CancelRead(0)
				return true
			}
			return false
		}, ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, b, l, r, bc, tr := streamScenario(t, mixedSizes(40), tc.fn)
			res, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 4})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Pull = %v, want %v", err, tc.want)
			}
			if !res.Stats.Streamed {
				t.Fatal("the pull was not streamed")
			}
			ends := tr.ending()
			if len(ends) < k {
				t.Fatalf("the server sent %d answers, want at least %d", len(ends), k)
			}
			if r.Len() != ends[k-1] {
				t.Fatalf("Len %d, want %d: the answers before the bad one", r.Len(), ends[k-1])
			}
			if _, err := r.Head(); !errors.Is(err, kololog.ErrNoHead) {
				t.Fatalf("Head %v: a failed pull has no head", err)
			}
			resume(t, a, b, l, r)
		})
	}
}

// A proof of the wrong history is a bad proof, not a fork, and nothing of the answer it ends is stored.
func TestStreamBadProof(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := sizedLog(t, a, mixedSizes(40))
	a.srv.Offer(l)
	r := openReplica(t, b, l)
	bc, cb := connect(t, b, c, nil)
	src := tamper{Source: l, proof: func(p *kololog.ConsistencyProof) {
		if len(p.Path) > 0 && p.OldSize >= 9 {
			p.Path[0][0] ^= 1
		}
	}}
	serveStreamScript(t, cb, src, nil)
	_, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 4})
	if !errors.Is(err, ErrInvalid) || errors.Is(err, ErrDiverged) {
		t.Fatalf("Pull = %v, want ErrInvalid", err)
	}
	if r.Len() == 0 || r.Len() >= l.Len() {
		t.Fatalf("Len %d of %d: want a stored prefix", r.Len(), l.Len())
	}
	resume(t, a, b, l, r)
}

// A peer that stalls in the middle of an answer ends the pull with ErrTimeout after the answers before it are stored.
func TestStreamStalledAnswer(t *testing.T) {
	checkGoroutines(t)
	_, _, _, r, bc, tr := streamScenario(t, []int{1200 << 10, 20 << 10, 20 << 10}, func(st *kolotransport.Stream, kind byte, n int, real []byte) bool {
		if kind == 'E' && n == 1 {
			st.Write(real[:len(real)/2])
			time.Sleep(2 * timeout)
			return true
		}
		return false
	})
	_, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 4})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Pull = %v, want ErrTimeout", err)
	}
	if first := tr.ending()[0]; r.Len() != first {
		t.Fatalf("Len %d, want %d, the end of the first answer", r.Len(), first)
	}
}

// An answer that is slow but keeps moving is read, with the credit of the next ones in flight.
func TestStreamSlowAnswerIsRead(t *testing.T) {
	checkGoroutines(t)
	_, _, l, r, bc, _ := streamScenario(t, []int{60 << 10, 60 << 10}, func(st *kolotransport.Stream, kind byte, n int, real []byte) bool {
		if kind != 'E' || n != 0 {
			return false
		}
		for len(real) > 0 {
			k := min(len(real), 25<<10)
			st.Write(real[:k])
			real = real[k:]
			time.Sleep(1100 * time.Millisecond)
		}
		return true
	})
	if _, err := PullWith(testCtx(t), bc, r, &PullOptions{InFlight: 4}); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
}

// Cancelling, or a deadline, in the middle of a stream returns the context's error at once, leaks nothing and leaves a
// replica that a later pull completes.
func TestStreamCancel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		depth int
		delay time.Duration // of each commit
		limit time.Duration // of the pull's context, 0 for none
	}{
		{"cancel, depth 1", 1, 5 * time.Millisecond, 0},
		{"cancel, depth 3", 3, 5 * time.Millisecond, 0},
		{"cancel, depth 8", MaxInFlight, 5 * time.Millisecond, 0},
		{"cancel, slow commits", 4, 200 * time.Millisecond, 0},
		{"deadline", 3, 5 * time.Millisecond, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, c := newPeer(t), newPeer(t)
			b, _ := slowPeer(t, tc.delay)
			c.srv = nil
			l := sizedLog(t, a, mixedSizes(60))
			a.srv.Offer(l)
			r := openReplica(t, b, l)
			bc, cb := connect(t, b, c, nil)
			tr := serveStreamScript(t, cb, l, func(_ *kolotransport.Stream, kind byte, _ int, _ []byte) bool {
				if kind == 'E' {
					time.Sleep(150 * time.Millisecond)
				}
				return false
			})
			ctx, cancel := context.WithCancel(testCtx(t))
			defer cancel()
			want := context.Canceled
			var cancelled atomic.Int64
			if tc.limit != 0 {
				ctx, cancel = context.WithTimeout(ctx, tc.limit)
				defer cancel()
				want = context.DeadlineExceeded
			} else {
				go func() {
					for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && len(tr.ending()) < 4; {
						time.Sleep(5 * time.Millisecond)
					}
					cancelled.Store(time.Now().UnixNano())
					cancel()
				}()
			}
			_, err := PullWith(ctx, bc, r, &PullOptions{InFlight: tc.depth})
			if !errors.Is(err, want) {
				t.Fatalf("Pull = %v, want %v", err, want)
			}
			if r.Len() >= l.Len() {
				t.Fatalf("Len %d of %d: the pull was not cut in the middle", r.Len(), l.Len())
			}
			if at := cancelled.Load(); at != 0 && time.Since(time.Unix(0, at)) > 3*time.Second {
				t.Fatalf("Pull returned %v after the cancel", time.Since(time.Unix(0, at)))
			}
			resume(t, a, b, l, r)
		})
	}
}

// A peer that sends answers of the largest size one after another, while commits are slow, never makes the pull hold more
// than readAhead, or than one answer if that is larger.
func TestStreamMemoryIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sizes []int
		most  int
	}{
		{"1 MiB entries", repeat(1<<20, 24), readAhead},
		{"2 MiB entries", repeat(2<<20, 12), readAhead},
		{"3 MiB entries", repeat(3<<20, 8), 4 << 20},
		{"4 KiB entries", repeat(4<<10, 1500), readAhead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a := newPeer(t)
			b, _ := slowPeer(t, 20*time.Millisecond)
			l := sizedLog(t, a, tc.sizes)
			a.srv.Offer(l)
			ba, _ := connect(t, b, a, nil)
			r := replica(t, b, ba, a.id.PublicKey(), l.ID())
			res, err := PullWith(testCtx(t), ba, r, &PullOptions{InFlight: MaxInFlight})
			if err != nil {
				t.Fatal(err)
			}
			sameEntries(t, r, l)
			if h := res.Stats.HeldMax; h > tc.most || h == 0 {
				t.Fatalf("held %d bytes at most, want 1 to %d", h, tc.most)
			}
			if res.Stats.MemoryBlocked == 0 && tc.sizes[0] >= 1<<20 {
				t.Fatalf("the reader never waited for memory: %+v", res.Stats)
			}
		})
	}
}

func repeat(n, times int) []int {
	out := make([]int, times)
	for i := range out {
		out[i] = n + i
	}
	return out
}

// A peer whose history forks from the entries the replica holds is found during a stream: the answers still on the
// stream are read before the peer's record is asked for, and the pull ends with ErrDiverged and the replica as it was.
func TestStreamFindsAFork(t *testing.T) {
	for _, depth := range []int{1, 3, MaxInFlight} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			checkGoroutines(t)
			a, b, c, d := newPeer(t), newPeer(t), newPeer(t), newPeer(t)
			c.srv = nil
			ra, rb := bigForks(t, a.id, 3, mixedSizes(40))
			hdr := ra.Header()
			r, err := b.st.OpenReplica(hdr.LogKey, ra.ID(), hdr.Encode())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { r.Close() })
			// The replica holds the first answers of one branch, from a pull that was cut off.
			bc, cb := connect(t, b, c, nil)
			serveStreamScript(t, cb, ra, func(st *kolotransport.Stream, kind byte, n int, _ []byte) bool {
				if kind == 'E' && n == 3 {
					st.Close()
					st.CancelRead(0)
					return true
				}
				return false
			})
			if err := Pull(testCtx(t), bc, r); err == nil || r.Len() <= 3 {
				t.Fatalf("Pull = %v, Len %d: the cut pull must fail with entries past the shared ones", err, r.Len())
			}
			before := snapshot(t, r)
			if err := d.srv.Offer(rb); err != nil {
				t.Fatal(err)
			}
			bd, _ := connect(t, b, d, nil)
			_, err = PullWith(testCtx(t), bd, r, &PullOptions{InFlight: depth})
			if !errors.Is(err, ErrDiverged) {
				t.Fatalf("Pull = %v, want ErrDiverged", err)
			}
			if after := snapshot(t, r); after != before {
				t.Fatalf("replica changed: %s, was %s", after, before)
			}
		})
	}
}

// A pull with NoMarkers that meets a marker among streamed answers asks for the proof of the entries before it, and stops
// there with the replica as at any other depth, over the stream that is left.
func TestStreamNoMarkersAsksForTheProofOfTheShorterAnswer(t *testing.T) {
	for _, at := range []uint64{1, 4, 11} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			checkGoroutines(t)
			a, b, c := newPeer(t), newPeer(t), newPeer(t)
			c.srv = nil
			l := sizedLog(t, a, mixedSizes(30))
			if err := l.Delete(at); err != nil {
				t.Fatal(err)
			}
			a.srv.Offer(l)
			r := openReplica(t, b, l)
			bc, cb := connect(t, b, c, nil)
			tr := serveStreamScript(t, cb, l, nil)
			res, err := PullWith(testCtx(t), bc, r, &PullOptions{NoMarkers: true, InFlight: 4})
			if !errors.Is(err, ErrMarked) {
				t.Fatalf("Pull = %v, want ErrMarked", err)
			}
			if r.Len() != at || !res.Stats.Streamed {
				t.Fatalf("Len %d, want %d; streamed %v", r.Len(), at, res.Stats.Streamed)
			}
			// The proof for the entries before the marker is asked for on the same stream, after the stream is drained,
			// unless the marker starts an answer, whose proof the peer sent.
			proofs := tr.requests(tProofReq)
			boundary := slices.Contains(tr.ending(), at)
			if boundary && len(proofs) != 0 || !boundary && (len(proofs) != 1 || proofs[0].a != at) {
				t.Fatalf("PROOF_REQs %+v, want one for the end at %d unless that ends an answer (%v)", proofs, at, boundary)
			}
			resume(t, a, b, l, r)
		})
	}
}

// The credit of a stream is for ENTRIES answers only: STATE and PROOF requests that follow are answered as before.
func TestStreamThenCalls(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := sizedLog(t, a, mixedSizes(20))
	l.Delete(3)
	a.srv.Offer(l)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	res, err := PullWith(testCtx(t), ba, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	sameLog(t, r, l)
	if !res.Stats.Streamed {
		t.Fatal("not streamed")
	}
	if info, err := r.EntryInfo(3); err != nil || !info.Deleted {
		t.Fatalf("entry 3: %+v, %v", info, err)
	}
}

// A pull that fills a target and then the head, two fills on one stream, streams both.
func TestStreamTwoFills(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	c.srv = nil
	l := sizedLog(t, a, mixedSizes(30))
	a.srv.Offer(l)
	r := openReplica(t, b, l)
	// Cut a pull so the replica has a target, then pull from a peer that holds more.
	bc, cb := connect(t, b, c, nil)
	serveStreamScript(t, cb, l, func(st *kolotransport.Stream, kind byte, n int, _ []byte) bool {
		if kind == 'E' && n == 2 {
			st.Close()
			st.CancelRead(0)
			return true
		}
		return false
	})
	if err := Pull(testCtx(t), bc, r); err == nil {
		t.Fatal("Pull succeeded on a cut stream")
	}
	appendN(t, l, 5)
	ba, _ := connect(t, b, a, nil)
	res, err := PullWith(testCtx(t), ba, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
	if res.Stats.Requests == 0 || !res.Stats.Streamed {
		t.Fatalf("stats %+v", res.Stats)
	}
}

// The largest entry a peer can serve, with small ones around it, is pulled whole in a streamed answer of its own, whose proof
// comes in a message after it.
func TestStreamLargestEntry(t *testing.T) {
	checkGoroutines(t)
	a, b, probe := newPeer(t), newPeer(t), newPeer(t)
	// Find the largest value, in steps of 16 KiB, that one answer can hold, in a log of its own.
	largest := 0
	for n := MaxMessageSize; n > MaxMessageSize-1<<20 && largest == 0; n -= 16 << 10 {
		pl, err := probe.st.Create(probe.id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pl.Append(make([]byte, n)); err == nil {
			if m, code := entries(pl, true, 0, 0, 0); code == 0 && len(wire(m)) <= MaxMessageSize+4 {
				largest = n
			}
		}
		pl.Close()
	}
	if largest == 0 {
		t.Fatal("no entry of about 4 MiB fits an answer")
	}
	l, err := a.st.Create(a.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	appendN(t, l, 3)
	if _, err := l.Append(make([]byte, largest)); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 3)
	a.srv.Offer(l)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	res, err := PullWith(testCtx(t), ba, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
	if !res.Stats.Streamed || res.Stats.HeldMax < largest {
		t.Fatalf("stats %+v for an entry of %d bytes", res.Stats, largest)
	}
}
