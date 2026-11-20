package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	"github.com/ciranda-dev/kolo-sync/internal/v017"
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

// oldServerFor links b to an end that serves l with the code of v0.1.7, which gives access to every peer, and returns b's end.
func oldServerFor(t *testing.T, b, owner *peer, l *kolostore.Log, access v017.Access) *kolosecure.Conn {
	t.Helper()
	srv := v017.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) v017.Access { return access })
	if err := srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", owner.id, nil)
	if err != nil {
		t.Fatal(err)
	}
	acc := make(chan *kolosecure.Conn, 1)
	go func() {
		c, _ := ln.Accept(ctx)
		acc <- c
	}()
	bc, err := kolosecure.Dial(ctx, ln.Addr().String(), b.id, owner.id.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	oc := <-acc
	var wg sync.WaitGroup
	wg.Go(func() { srv.Serve(ctx, oc) })
	t.Cleanup(func() {
		cancel()
		bc.Close()
		oc.Close()
		ln.Close()
		wg.Wait()
	})
	return bc
}

// Every pairing of this version and v0.1.7, client and server, ends with the same replica; a new client of an old server
// asks once with STREAM_REQ, is refused as a peer that does not know it refuses, and asks again on a new stream as v0.1.7 does.
func TestCompatibilityMatrix(t *testing.T) {
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
		for _, oldClient := range []bool{false, true} {
			for _, oldSrv := range []bool{false, true} {
				for _, depth := range []int{0, 1, 4} {
					t.Run(fmt.Sprintf("%s old client %v old server %v depth %d", name, oldClient, oldSrv, depth), func(t *testing.T) {
						checkGoroutines(t)
						a, b := newPeer(t), newPeer(t)
						l := mk(t, a)
						var conn *kolosecure.Conn
						if oldSrv {
							conn = oldServerFor(t, b, a, l, v017.Keys)
						} else {
							a.srv.Offer(l)
							conn, _ = connect(t, b, a, nil)
						}
						r := replica(t, b, conn, a.id.PublicKey(), l.ID())
						cc := &countConn{Conn: conn}
						var streamed bool
						if oldClient {
							if _, err := v017.PullWith(testCtx(t), cc, r, &v017.PullOptions{InFlight: depth}); err != nil {
								t.Fatal(err)
							}
						} else {
							res, err := PullWith(testCtx(t), cc, r, &PullOptions{InFlight: depth})
							if err != nil {
								t.Fatal(err)
							}
							streamed = res.Stats.Streamed
						}
						sameLog(t, r, l)
						wantStreamed, opened := !oldClient && !oldSrv, int64(1)
						if !oldClient && oldSrv {
							opened = 2
						}
						if streamed != wantStreamed {
							t.Fatalf("streamed %v, want %v", streamed, wantStreamed)
						}
						if got := cc.opened.Load(); got != opened {
							t.Fatalf("%d streams opened, want %d", got, opened)
						}
					})
				}
			}
		}
	}
}

// A new client pulls ciphertext and with NoMarkers from an old server, through the fallback, with the same results as from a new one.
func TestCompatibilityOptionsAgainstAnOldServer(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := sizedLog(t, a, mixedSizes(30))
	if err := l.Delete(9); err != nil {
		t.Fatal(err)
	}
	conn := oldServerFor(t, b, a, l, v017.Ciphertext)
	r := replica(t, b, conn, a.id.PublicKey(), l.ID())
	res, err := PullWith(testCtx(t), conn, r, &PullOptions{NoMarkers: true})
	if !errors.Is(err, ErrMarked) || r.Len() != 9 || res.Stats.Streamed {
		t.Fatalf("NoMarkers: %v, Len %d, streamed %v", err, r.Len(), res.Stats.Streamed)
	}
	if err := PullCiphertext(testCtx(t), conn, r); err != nil {
		t.Fatal(err)
	}
	sameHead(t, r, l)
	// The fallback is by pull: the next pull of an old server asks with STREAM_REQ once more and falls back again.
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

// An old server refuses STREAM_REQ the way a stream of this version never does: with ERROR 4 and then the end of the stream.
func TestOldServerAnswersStreamReqWithAnError(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := sizedLog(t, a, mixedSizes(5))
	conn := oldServerFor(t, b, a, l, v017.Keys)
	st := rawStream(t, conn)
	if _, err := writeMsg(st, headReq(a.id.PublicKey(), l.ID())); err != nil {
		t.Fatal(err)
	}
	if m, err := readMsg(st, false); err != nil || m.typ != tHead {
		t.Fatalf("HEAD: %+v, %v", m, err)
	}
	if _, err := writeMsg(st, message{typ: tStreamReq, a: 0, size: l.Len(), keys: true, credit: requestCredit}); err != nil {
		t.Fatal(err)
	}
	m, err := readMsg(st, false)
	if err != nil || m.typ != tError || m.code != codeProtocol {
		t.Fatalf("answer %+v, %v, want ERROR 4", m, err)
	}
	if _, err := readMsg(st, false); err == nil {
		t.Fatal("the old server kept the stream open after ERROR 4")
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
