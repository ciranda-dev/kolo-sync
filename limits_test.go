package kolosync

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func allowAll(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Keys }

// limited returns a peer that serves a log of entries of the given sizes with opts.
func limited(t *testing.T, opts *ServerOptions, sizes []int) (*peer, *kolostore.Log) {
	t.Helper()
	a := newPeer(t)
	srv, err := NewServerWith(allowAll, opts)
	if err != nil {
		t.Fatal(err)
	}
	a.srv = srv
	l := sizedLog(t, a, sizes)
	if err := srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	return a, l
}

// dial is a new peer on its own connection to a: it opens a stream and sends HEAD_REQ. It returns the stream and the
// first answer, a HEAD or the ERROR that refused the stream.
func dial(t *testing.T, a *peer, l *kolostore.Log) (*kolotransport.Stream, message) {
	t.Helper()
	conn, _ := connect(t, newPeer(t), a, nil)
	st := rawStream(t, conn)
	if _, err := writeMsg(st, headReq(a.id.PublicKey(), l.ID())); err != nil {
		t.Fatal(err)
	}
	m, err := readMsg(st, false)
	if err != nil {
		t.Fatal(err)
	}
	return st, m
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestNewServerWith(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts *ServerOptions
		ok   bool
	}{
		{"nil", nil, true},
		{"zero", &ServerOptions{}, true},
		{"set", &ServerOptions{MaxTotalStreams: 1, MaxAnswerBytes: 2 * MaxMessageSize}, true},
		{"negative streams", &ServerOptions{MaxTotalStreams: -1}, false},
		{"negative bytes", &ServerOptions{MaxAnswerBytes: -1}, false},
		{"bytes below one largest answer", &ServerOptions{MaxAnswerBytes: 2*MaxMessageSize - 1}, false},
		{"watched set", &ServerOptions{MaxWatched: maxWatchItems, WatchGap: 10 * time.Millisecond}, true},
		{"watched at the largest gap", &ServerOptions{WatchGap: 10 * time.Second}, true},
		{"negative watched", &ServerOptions{MaxWatched: -1}, false},
		{"watched below one request", &ServerOptions{MaxWatched: maxWatchItems - 1}, false},
		{"negative gap", &ServerOptions{WatchGap: -time.Millisecond}, false},
		{"gap below 10 ms", &ServerOptions{WatchGap: 9 * time.Millisecond}, false},
		{"gap above 10 s", &ServerOptions{WatchGap: 10*time.Second + 1}, false},
	} {
		s, err := NewServerWith(allowAll, tc.opts)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrInvalidArgument)) || (err == nil) != (s != nil) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	s := NewServer(allowAll)
	if s.limits.MaxTotalStreams != DefaultMaxTotalStreams || s.limits.MaxAnswerBytes != DefaultMaxAnswerBytes ||
		s.limits.MaxWatched != DefaultMaxWatched || s.limits.WatchGap != DefaultWatchGap {
		t.Fatalf("defaults %+v", s.limits)
	}
}

// Streams over many connections of hostile peers stop at MaxTotalStreams, the rest are answered busy, and a slot a
// peer gives back is used again.
func TestServerTotalStreamCap(t *testing.T) {
	checkGoroutines(t)
	const cap = 5
	a, l := limited(t, &ServerOptions{MaxTotalStreams: cap}, []int{100, 100})
	var held []*kolotransport.Stream
	busy := 0
	for range 3 * cap {
		st, m := dial(t, a, l)
		switch {
		case m.typ == tHead:
			held = append(held, st)
		case m.typ == tError && m.code == codeBusy:
			busy++
		default:
			t.Fatalf("answer %+v", m)
		}
	}
	if len(held) != cap || busy != 2*cap {
		t.Fatalf("%d streams served and %d refused, want %d and %d", len(held), busy, cap, 2*cap)
	}
	if s := a.srv.Stats(); s.ActiveStreams != cap || s.RefusedByLimit != uint64(2*cap) {
		t.Fatalf("stats %+v", s)
	}
	end(held[0])
	waitFor(t, "a slot to be free", func() bool { return a.srv.taken.Load() == cap-1 })
	if st, m := dial(t, a, l); m.typ != tHead {
		t.Fatalf("after a slot was given back: %+v", m)
	} else {
		held = append(held, st)
	}
	for _, st := range held {
		end(st)
	}
	waitFor(t, "every slot to be free", func() bool { return a.srv.taken.Load() == 0 && a.srv.Stats().ActiveStreams == 0 })
}

// Streams that ask for answers and never read hold at most MaxAnswerBytes between them, the others are answered busy
// before the log is read, and the memory is given back when the peers go.
func TestServerAnswerBytesCap(t *testing.T) {
	for _, mode := range []string{"stream", "entries"} {
		t.Run(mode, func(t *testing.T) {
			checkGoroutines(t)
			const limit = 2 * MaxMessageSize
			a, l := limited(t, &ServerOptions{MaxAnswerBytes: limit}, repeat(256<<10, 16))
			size := l.Len()
			var sts []*kolotransport.Stream
			for range 10 {
				st, m := dial(t, a, l)
				if m.typ != tHead {
					t.Fatalf("answer %+v", m)
				}
				req := message{typ: tStreamReq, size: size, keys: true, credit: maxCredit}
				if mode == "entries" {
					req = message{typ: tEntriesReq, b: size - 1, keys: true}
				}
				if _, err := writeMsg(st, req); err != nil {
					t.Fatal(err)
				}
				sts = append(sts, st)
				if held := a.srv.Stats().AnswerBytes; held > limit {
					t.Fatalf("answers hold %d bytes, limit %d", held, limit)
				}
			}
			waitFor(t, "a refusal", func() bool { return a.srv.Stats().RefusedByLimit > 0 })
			time.Sleep(200 * time.Millisecond)
			if s := a.srv.Stats(); s.AnswerBytes > limit || s.AnswerBytes == 0 {
				t.Fatalf("answers hold %d bytes, limit %d", s.AnswerBytes, limit)
			}
			refused := 0
			for _, st := range sts {
				st.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				if m, err := readMsg(st, false); err == nil && m.typ == tError && m.code == codeBusy {
					refused++
				}
			}
			if refused == 0 || uint64(refused) != a.srv.Stats().RefusedByLimit {
				t.Fatalf("%d clients read busy, server counted %d", refused, a.srv.Stats().RefusedByLimit)
			}
			for _, st := range sts {
				end(st)
			}
			waitFor(t, "the memory to be given back", func() bool {
				s := a.srv.Stats()
				return s.AnswerBytes == 0 && s.ActiveStreams == 0
			})
			b := newPeer(t)
			conn, _ := connect(t, b, a, nil)
			r := replica(t, b, conn, a.id.PublicKey(), l.ID())
			if err := Pull(testCtx(t), conn, r); err != nil || r.Len() != size {
				t.Fatalf("Pull after the peers left: %v, %d entries", err, r.Len())
			}
		})
	}
}

// The client of a server that is over a limit gets ErrBusy, as it does for MaxStreams.
func TestServerLimitIsErrBusy(t *testing.T) {
	checkGoroutines(t)
	a, l := limited(t, &ServerOptions{MaxTotalStreams: 1}, []int{100})
	if st, m := dial(t, a, l); m.typ != tHead {
		t.Fatalf("answer %+v", m)
	} else {
		defer end(st)
	}
	b := newPeer(t)
	conn, _ := connect(t, b, a, nil)
	r, err := b.st.OpenReplica(a.id.PublicKey(), l.ID(), l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err := Pull(testCtx(t), conn, r); !errors.Is(err, ErrBusy) {
		t.Fatalf("Pull = %v, want ErrBusy", err)
	}
}

// An answer larger than the room reserved before it was built asks for the rest afterwards, and is refused, and its
// entries wiped, if the rest is not there.
func TestServerAnswerBytesGrowsToTheAnswer(t *testing.T) {
	checkGoroutines(t)
	const limit = 2 * MaxMessageSize
	a, l := limited(t, &ServerOptions{MaxAnswerBytes: limit}, []int{3 << 20, 3 << 20})
	req := message{typ: tEntriesReq, a: 0, b: 0, keys: true}
	first, m := dial(t, a, l)
	if m.typ != tHead {
		t.Fatalf("answer %+v", m)
	}
	if _, err := writeMsg(first, req); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first answer to be held", func() bool { return a.srv.Stats().AnswerBytes > 2*3<<20 })
	second, m := dial(t, a, l)
	if m.typ != tHead {
		t.Fatalf("answer %+v", m)
	}
	if _, err := writeMsg(second, req); err != nil {
		t.Fatal(err)
	}
	second.SetReadDeadline(time.Now().Add(timeout))
	if m, err := readMsg(second, false); err != nil || m.typ != tError || m.code != codeBusy {
		t.Fatalf("second answer %+v, %v, want ERROR busy", m, err)
	}
	if s := a.srv.Stats(); s.AnswerBytes > limit || s.AnswerBytes < 2*3<<20 || s.RefusedByLimit != 1 {
		t.Fatalf("stats %+v", s)
	}
}
