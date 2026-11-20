package kolosync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// countConn counts the streams opened on it.
type countConn struct {
	Conn
	opened atomic.Int64
}

func (c *countConn) OpenStream(ctx context.Context) (*kolotransport.Stream, error) {
	c.opened.Add(1)
	return c.Conn.OpenStream(ctx)
}

// serveNoStream serves src on every stream of conn like a Server that does not know STREAM_REQ: the other requests are
// answered one at a time with every key, and STREAM_REQ gets ERROR 4 and the end of the stream.
func serveNoStream(t *testing.T, conn *kolosecure.Conn, src Source) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			st, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			wg.Go(func() {
				defer end(st)
				if _, err := readMsg(st, true); err != nil {
					return
				}
				h, _ := src.Head()
				if _, err := writeMsg(st, message{typ: tHead, head: h.Encode(), header: src.Header().Encode()}); err != nil {
					return
				}
				st.SetWriteDeadline(time.Time{})
				for {
					req, err := readMsg(st, true)
					if err != nil {
						return
					}
					var resp message
					code := uint64(0)
					switch req.typ {
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
					if _, err := st.Write(wire(resp)); err != nil || code == codeProtocol {
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
}

// noStreamPeer links b to a peer that serves l without streaming and returns b's end.
func noStreamPeer(t *testing.T, b *peer, l *kolostore.Log) *kolosecure.Conn {
	t.Helper()
	a := newPeer(t)
	a.srv = nil
	bc, ac := connect(t, b, a, nil)
	serveNoStream(t, ac, l)
	return bc
}

// A pull of a peer that does not know STREAM_REQ asks once with STREAM_REQ, is refused, and asks again on a new stream, one
// answer at a time, and ends with the same replica as a pull of a peer that streams.
func TestFallbackWhenThePeerDoesNotStream(t *testing.T) {
	logs := map[string]func(t *testing.T, p *peer) *kolostore.Log{
		"mixed": func(t *testing.T, p *peer) *kolostore.Log { return sizedLog(t, p, mixedSizes(40)) },
		"marker": func(t *testing.T, p *peer) *kolostore.Log {
			l := sizedLog(t, p, mixedSizes(25))
			if err := l.Delete(7); err != nil {
				t.Fatal(err)
			}
			return l
		},
		"one entry": func(t *testing.T, p *peer) *kolostore.Log { return sizedLog(t, p, []int{300}) },
		"big": func(t *testing.T, p *peer) *kolostore.Log {
			return sizedLog(t, p, []int{3 << 20, 100, 3 << 20, 4 << 10})
		},
	}
	for name, mk := range logs {
		for _, depth := range []int{0, 1, 4} {
			for _, streams := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s depth %d streams %v", name, depth, streams), func(t *testing.T) {
					checkGoroutines(t)
					a, b := newPeer(t), newPeer(t)
					l := mk(t, a)
					var conn *kolosecure.Conn
					if streams {
						a.srv.Offer(l)
						conn, _ = connect(t, b, a, nil)
					} else {
						conn = noStreamPeer(t, b, l)
					}
					r := replica(t, b, conn, a.id.PublicKey(), l.ID())
					cc := &countConn{Conn: conn}
					res, err := PullWith(testCtx(t), cc, r, &PullOptions{InFlight: depth})
					if err != nil {
						t.Fatal(err)
					}
					sameLog(t, r, l)
					wantOpened := int64(1)
					if !streams {
						wantOpened = 2
					}
					if res.Stats.Streamed != streams {
						t.Fatalf("streamed %v, want %v", res.Stats.Streamed, streams)
					}
					if got := cc.opened.Load(); got != wantOpened {
						t.Fatalf("%d streams opened, want %d", got, wantOpened)
					}
				})
			}
		}
	}
}

// A pull with NoMarkers or PullCiphertext of a peer that does not stream, through the fallback, has the same results as of one that does.
func TestFallbackOptions(t *testing.T) {
	checkGoroutines(t)
	b := newPeer(t)
	a := newPeer(t)
	l := sizedLog(t, a, mixedSizes(30))
	if err := l.Delete(9); err != nil {
		t.Fatal(err)
	}
	conn := noStreamPeer(t, b, l)
	r := replica(t, b, conn, a.id.PublicKey(), l.ID())
	res, err := PullWith(testCtx(t), conn, r, &PullOptions{NoMarkers: true})
	if !errors.Is(err, ErrMarked) || r.Len() != 9 || res.Stats.Streamed {
		t.Fatalf("NoMarkers: %v, Len %d, streamed %v", err, r.Len(), res.Stats.Streamed)
	}
	if err := PullCiphertext(testCtx(t), conn, r); err != nil {
		t.Fatal(err)
	}
	sameHead(t, r, l)
	// The fallback is by pull: the next pull asks with STREAM_REQ once more and falls back again.
	cc := &countConn{Conn: conn}
	appendN(t, l, 3)
	if err := PullCiphertext(testCtx(t), cc, r); err != nil {
		t.Fatal(err)
	}
	if got := cc.opened.Load(); got != 2 {
		t.Fatalf("%d streams opened, want 2", got)
	}
	sameHead(t, r, l)
}

// sameHead checks that r holds as many entries as l and the same head, for a replica that holds no keys.
func sameHead(t *testing.T, r, l interface {
	Len() uint64
	Head() (kololog.Head, error)
}) {
	t.Helper()
	h1, err1 := r.Head()
	h2, err2 := l.Head()
	if r.Len() != l.Len() || err1 != nil || err2 != nil || !bytes.Equal(h1.Encode(), h2.Encode()) {
		t.Fatalf("Len %d, want %d; heads %v %v", r.Len(), l.Len(), err1, err2)
	}
}

// Whatever the peer, an ERROR 4 to a later request of a pull that streams is an error, not a fallback.
func TestStreamErrorAfterTheFirstAnswerIsNotAFallback(t *testing.T) {
	checkGoroutines(t)
	_, _, _, r, bc, _ := streamScenario(t, mixedSizes(40), replaceAt('E', 1, func([]byte) []byte {
		return wire(message{typ: tError, code: codeProtocol})
	}))
	cc := &countConn{Conn: bc}
	res, err := PullWith(testCtx(t), cc, r, &PullOptions{InFlight: 3})
	if !errors.Is(err, ErrProtocol) || !res.Stats.Streamed || cc.opened.Load() != 1 {
		t.Fatalf("Pull = %v, streamed %v, %d streams", err, res.Stats.Streamed, cc.opened.Load())
	}
}
