package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestMain(m *testing.M) {
	timeout = 3 * time.Second
	os.Exit(m.Run())
}

// checkGoroutines fails the test if goroutines started after it are still running after the cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// peer is one node: an identity, a store and a server.
type peer struct {
	id  *koloid.Identity
	st  *kolostore.Store
	srv *Server
}

// newPeer returns a peer whose server gives Keys to every peer.
func newPeer(t *testing.T) *peer {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(kolostore.NewMemory())
	t.Cleanup(func() { st.Close() })
	return &peer{id: id, st: st, srv: NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Keys })}
}

// connect links a and b over loopback and runs each side's server, if any, on its end.
// It returns a's end and b's end.
func connect(t *testing.T, a, b *peer, cfg *kolosecure.Config) (*kolosecure.Conn, *kolosecure.Conn) {
	t.Helper()
	return link(t, a, b, cfg, func(c *kolosecure.Conn) *kolosecure.Conn { return c })
}

// connectRelayed is connect with each end seen through a relayed Conn.
func connectRelayed(t *testing.T, a, b *peer) (*relayed, *relayed) {
	t.Helper()
	return link(t, a, b, nil, func(c *kolosecure.Conn) *relayed { return &relayed{ic: c} })
}

// link is connect with each end passed through wrap before the servers use it.
func link[C Conn](t *testing.T, a, b *peer, cfg *kolosecure.Config, wrap func(*kolosecure.Conn) C) (C, C) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", b.id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		c   *kolosecure.Conn
		err error
	}
	acc := make(chan res, 1)
	go func() {
		c, err := l.Accept(ctx)
		acc <- res{c, err}
	}()
	ab, err := kolosecure.Dial(ctx, l.Addr().String(), a.id, b.id.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := <-acc
	if r.err != nil {
		t.Fatal(r.err)
	}
	ba := r.c
	xa, xb := wrap(ab), wrap(ba)
	var wg sync.WaitGroup
	for _, s := range []struct {
		srv  *Server
		conn C
	}{{a.srv, xa}, {b.srv, xb}} {
		if s.srv != nil {
			wg.Go(func() { s.srv.Serve(ctx, s.conn) })
		}
	}
	t.Cleanup(func() {
		cancel()
		ab.Close()
		ba.Close()
		l.Close()
		wg.Wait()
	})
	return xa, xb
}

// ownLog creates a log in p's store with values "0" to "n-1" and offers it.
func ownLog(t *testing.T, p *peer, n int) *kolostore.Log {
	t.Helper()
	l, err := p.st.Create(p.id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	appendN(t, l, n)
	if err := p.srv.Offer(l); err != nil {
		t.Fatal(err)
	}
	return l
}

func appendN(t testing.TB, l interface{ Append(any) (uint64, error) }, n int) {
	t.Helper()
	for i := range n {
		if _, err := l.Append([]byte(fmt.Sprintf("entry %d", i))); err != nil {
			t.Fatal(err)
		}
	}
}

// replica opens p's replica of the log logID owned by owner, fetching its header over conn.
func replica(t *testing.T, p *peer, conn Conn, owner ed25519.PublicKey, logID kololog.LogID) *kolostore.Replica {
	t.Helper()
	h, err := FetchHeader(testCtx(t), conn, owner, logID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.st.OpenReplica(owner, logID, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// reader is what sameEntries compares: a log or a replica.
type reader interface {
	Len() uint64
	Head() (kololog.Head, error)
	Get(uint64) ([]byte, error)
}

// sameEntries checks that r holds exactly the entries and head of want.
func sameEntries(t *testing.T, r, want reader) {
	t.Helper()
	if r.Len() != want.Len() {
		t.Fatalf("Len %d, want %d", r.Len(), want.Len())
	}
	h1, err1 := r.Head()
	h2, err2 := want.Head()
	if err1 != nil || err2 != nil || !bytes.Equal(h1.Encode(), h2.Encode()) {
		t.Fatalf("heads differ: %v %v", err1, err2)
	}
	for i := range want.Len() {
		a, err := r.Get(i)
		if err != nil {
			t.Fatalf("Get(%d): %v", i, err)
		}
		b, _ := want.Get(i)
		if !bytes.Equal(a, b) {
			t.Fatalf("entry %d differs", i)
		}
	}
}

// snapshot is a replica's head and length, to check that it did not change.
func snapshot(t *testing.T, r *kolostore.Replica) string {
	t.Helper()
	h, err := r.Head()
	return fmt.Sprintf("%d %x %v", r.Len(), h.Encode(), err)
}

// rawStream opens a stream on conn for a test that speaks the wire format itself.
func rawStream(t *testing.T, conn *kolosecure.Conn) *kolotransport.Stream {
	t.Helper()
	st, err := conn.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { end(st) })
	return st
}

// oldPulls makes the pulls of the test ask for one answer at a time, as they do of a peer that predates STREAM_REQ, which
// is what the scripted servers of the tests are.
func oldPulls(t *testing.T) {
	t.Helper()
	was := streamPulls
	streamPulls = false
	t.Cleanup(func() { streamPulls = was })
}

func rawServe(t *testing.T, conn *kolosecure.Conn, fn func(st *kolotransport.Stream)) {
	t.Helper()
	oldPulls(t)
	acceptServe(t, conn, fn)
}

// acceptServe answers the next stream on conn with fn.
func acceptServe(t *testing.T, conn *kolosecure.Conn, fn func(st *kolotransport.Stream)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer end(st)
		fn(st)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func headReq(owner ed25519.PublicKey, logID kololog.LogID) message {
	m := message{typ: tHeadReq, logID: logID}
	copy(m.owner[:], owner)
	return m
}
