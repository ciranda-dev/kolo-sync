package kolosync

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"

	koloid "github.com/ciranda-dev/kolo-id"
)

const testGap = 20 * time.Millisecond

// watchPeer is a peer whose server has opts, with WatchGap testGap unless opts sets one, and authorize.
func watchPeer(t *testing.T, opts ServerOptions, authorize func(peer, owner ed25519.PublicKey, logID kololog.LogID) Access) *peer {
	t.Helper()
	if opts.WatchGap == 0 {
		opts.WatchGap = testGap
	}
	if authorize == nil {
		authorize = allowAll
	}
	p := newPeer(t)
	srv, err := NewServerWith(authorize, &opts)
	if err != nil {
		t.Fatal(err)
	}
	p.srv = srv
	return p
}

// watchClient is a raw client of a server's watch stream.
type watchClient struct {
	t  *testing.T
	st *kolotransport.Stream
}

func newWatchClient(t *testing.T, a *peer) *watchClient {
	t.Helper()
	conn, _ := connect(t, newPeer(t), a, nil)
	return &watchClient{t: t, st: rawStream(t, conn)}
}

func named(owner *peer, id kololog.LogID, held uint64) watchItem {
	it := watchItem{logID: id, held: held}
	copy(it.owner[:], owner.id.PublicKey())
	return it
}

func (c *watchClient) send(items ...watchItem) {
	c.t.Helper()
	if _, err := writeMsg(c.st, message{typ: tWatchReq, watch: items}); err != nil {
		c.t.Fatal(err)
	}
}

func (c *watchClient) read() message {
	c.t.Helper()
	m, err := readMsg(c.st, false)
	if err != nil {
		c.t.Fatal(err)
	}
	return m
}

// heads reads one WATCH and returns its heads, decoded.
func (c *watchClient) heads() []kololog.Head {
	c.t.Helper()
	m := c.read()
	if m.typ != tWatch {
		c.t.Fatalf("answer %+v, want WATCH", m)
	}
	var out []kololog.Head
	for _, b := range m.heads {
		h, err := kololog.DecodeHead(b)
		if err != nil {
			c.t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}

// sizes reads one WATCH and returns the sizes of its heads, each checked against owner and its own log ID.
func (c *watchClient) sizes(owner *peer) []uint64 {
	c.t.Helper()
	var out []uint64
	for _, h := range c.heads() {
		if _, err := kololog.VerifyHead(owner.id.PublicKey(), h.LogID, h); err != nil {
			c.t.Fatalf("head does not verify: %v", err)
		}
		out = append(out, h.Size)
	}
	return out
}

func (c *watchClient) silent(d time.Duration) {
	c.t.Helper()
	c.st.SetReadDeadline(time.Now().Add(d))
	var b [1]byte
	if n, err := c.st.Read(b[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		c.t.Fatalf("read %d bytes, %v: the server sent a message", n, err)
	}
}

// ended checks that the server sent ERROR with code and then ended the stream.
func (c *watchClient) ended(code uint64) {
	c.t.Helper()
	if m := c.read(); m.typ != tError || m.code != code {
		c.t.Fatalf("answer %+v, want ERROR %d", m, code)
	}
	if m, err := readMsg(c.st, false); err == nil {
		c.t.Fatalf("the stream went on after the error: %+v", m)
	}
}

func TestWatchPushesGrowth(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{}, nil)
	l := ownLog(t, a, 3)
	c := newWatchClient(t, a)
	c.send(named(a, l.ID(), 3))
	if got := c.sizes(a); !slices.Equal(got, []uint64{3}) {
		t.Fatalf("first answer %v, want [3]", got)
	}
	c.silent(5 * testGap)
	appendN(t, l, 2)
	if got := c.sizes(a); !slices.Equal(got, []uint64{5}) {
		t.Fatalf("after growth %v, want [5]", got)
	}
	c.silent(5 * testGap)
	waitFor(t, "the answer memory to be given back", func() bool { return a.srv.Stats().AnswerBytes == 0 })
}

// The first answer holds the heads of the logs served at the size the watcher holds or more, and is sent, empty if need be.
func TestWatchFirstAnswer(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{}, nil)
	l1, l2 := ownLog(t, a, 3), ownLog(t, a, 3)
	c := newWatchClient(t, a)
	c.send(named(a, l1.ID(), 3), named(a, l2.ID(), 9), named(a, kololog.LogID{1}, 0))
	if got := c.heads(); len(got) != 1 || got[0].LogID != l1.ID() {
		t.Fatalf("first answer %+v, want the head of the first log only", got)
	}
	c.send(named(a, l2.ID(), 9))
	if got := c.heads(); len(got) != 0 {
		t.Fatalf("answer for a log the watcher is ahead of: %+v", got)
	}
	c.send(named(a, l2.ID(), 1))
	if got := c.sizes(a); !slices.Equal(got, []uint64{3}) {
		t.Fatalf("answer for a log the watcher is behind on: %v", got)
	}
}

// A log the peer may not read gets the answer of a missing one, and no push when it grows.
func TestWatchUnauthorizedLooksMissing(t *testing.T) {
	checkGoroutines(t)
	var denied kololog.LogID
	a := watchPeer(t, ServerOptions{}, func(_, _ ed25519.PublicKey, id kololog.LogID) Access {
		if id == denied {
			return NoAccess
		}
		return Keys
	})
	x, z := ownLog(t, a, 3), ownLog(t, a, 3)
	denied = x.ID()
	hidden, missing := newWatchClient(t, a), newWatchClient(t, a)
	hidden.send(named(a, x.ID(), 0))
	missing.send(named(a, kololog.LogID{7}, 0))
	if h, m := encode(hidden.read()), encode(missing.read()); !bytes.Equal(h, m) {
		t.Fatalf("unauthorized log answered %x, missing log %x", h, m)
	}
	both := newWatchClient(t, a)
	both.send(named(a, x.ID(), 0), named(a, z.ID(), 0))
	if got := both.heads(); len(got) != 1 || got[0].LogID != z.ID() {
		t.Fatalf("answer %+v, want the head of the readable log only", got)
	}
	appendN(t, x, 1)
	appendN(t, z, 1)
	if got := both.sizes(a); !slices.Equal(got, []uint64{4}) {
		t.Fatalf("push %v, want the readable log at 4", got)
	}
	hidden.silent(5 * testGap)
	missing.silent(5 * testGap)
}

// gated holds the probes of a log while its lock is held, so that a test can grow the log between two probes.
type gated struct {
	Source
	mu sync.RWMutex
}

func (g *gated) Record(i uint64) (kololog.Record, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Source.Record(i)
}

// Many appends between two probes make one push.
func TestWatchCoalesced(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{WatchGap: 50 * time.Millisecond}, nil)
	l := ownLog(t, a, 3)
	g := &gated{Source: l}
	if err := a.srv.Offer(g); err != nil {
		t.Fatal(err)
	}
	c := newWatchClient(t, a)
	c.send(named(a, l.ID(), 3))
	c.sizes(a)
	g.mu.Lock()
	appendN(t, l, 100)
	g.mu.Unlock()
	if got := c.sizes(a); !slices.Equal(got, []uint64{103}) {
		t.Fatalf("push %v, want one head at 103", got)
	}
	c.silent(5 * 50 * time.Millisecond)
}

// A stream is pushed to at most once per WatchGap, however soon after the last answer the log grows.
func TestWatchPushGap(t *testing.T) {
	checkGoroutines(t)
	const gap = 200 * time.Millisecond
	a := watchPeer(t, ServerOptions{WatchGap: gap}, nil)
	l := ownLog(t, a, 3)
	c := newWatchClient(t, a)
	c.send(named(a, l.ID(), 0))
	c.sizes(a)
	time.Sleep(gap * 6 / 10) // so that the next probe falls inside the gap that follows the second answer
	c.send(named(a, l.ID(), 0))
	c.sizes(a)
	answered := time.Now()
	appendN(t, l, 1)
	c.sizes(a)
	if d := time.Since(answered); d < gap*8/10 {
		t.Fatalf("the push came %v after the last answer, want at least %v", d, gap)
	}
}

func TestWatchBound(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{MaxWatched: maxWatchItems}, nil)
	var all []watchItem
	for i := range maxWatchItems {
		all = append(all, named(a, kololog.LogID{byte(i)}, 0))
	}
	c := newWatchClient(t, a)
	c.send(all...)
	c.heads()
	c.send(all[0]) // a log named again does not count again
	c.heads()
	c.send(named(a, kololog.LogID{byte(maxWatchItems)}, 0))
	c.ended(codeTooLarge)
}

func TestWatchRequestBounds(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{}, nil)
	var items []watchItem
	for i := range maxWatchItems + 1 {
		items = append(items, named(a, kololog.LogID{byte(i)}, 0))
	}
	c := newWatchClient(t, a)
	c.send(items...)
	c.ended(codeProtocol)
	c = newWatchClient(t, a)
	c.send(items[:1]...)
	c.heads()
	if _, err := c.st.Write(frame(maxSmall+1, nil)); err != nil {
		t.Fatal(err)
	}
	c.ended(codeTooLarge)
}

// counted counts the heads read from its log, each of which signs one if the log is ours.
type counted struct {
	Source
	heads atomic.Int64
}

func (c *counted) Head() (kololog.Head, error) {
	c.heads.Add(1)
	return c.Source.Head()
}

// A peer that names the same logs over and over makes no signature while they do not grow.
func TestWatchSignsOncePerGrowth(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{}, nil)
	var logs []*kolostore.Log
	var counts []*counted
	var items []watchItem
	for range 3 {
		l := ownLog(t, a, 3)
		cl := &counted{Source: l}
		if err := a.srv.Offer(cl); err != nil {
			t.Fatal(err)
		}
		logs, counts = append(logs, l), append(counts, cl)
		items = append(items, named(a, l.ID(), 0))
	}
	for i := len(items); i < maxWatchItems; i++ {
		items = append(items, named(a, kololog.LogID{byte(i)}, 0))
	}
	c := newWatchClient(t, a)
	for range 30 {
		c.send(items...)
		if got := c.heads(); len(got) != 3 {
			t.Fatalf("answer with %d heads, want 3", len(got))
		}
	}
	for i, cl := range counts {
		if n := cl.heads.Load(); n != 1 {
			t.Fatalf("log %d: Head read %d times, want 1", i, n)
		}
	}
	appendN(t, logs[0], 1)
	c.sizes(a)
	if n := counts[0].heads.Load(); n != 2 {
		t.Fatalf("grown log: Head read %d times, want 2", n)
	}
	if n := counts[1].heads.Load(); n != 1 {
		t.Fatalf("other log: Head read %d times, want 1", n)
	}
}

func TestWatchSecondStreamBusy(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{}, nil)
	conn, _ := connect(t, newPeer(t), a, nil)
	first := &watchClient{t: t, st: rawStream(t, conn)}
	second := &watchClient{t: t, st: rawStream(t, conn)}
	first.send(named(a, kololog.LogID{1}, 0))
	first.heads()
	second.send(named(a, kololog.LogID{1}, 0))
	second.ended(codeBusy)
}

// A watch stream takes one of the connection's MaxStreams slots.
func TestWatchHoldsOneSlot(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{}, nil)
	l := ownLog(t, a, 3)
	cfg := &kolosecure.Config{Transport: &kolotransport.Config{MaxIncomingStreams: 2 * MaxStreams}}
	conn, _ := connect(t, newPeer(t), a, cfg)
	w := &watchClient{t: t, st: rawStream(t, conn)}
	w.send(named(a, l.ID(), 0))
	w.heads()
	pull := func() message {
		st := rawStream(t, conn)
		if _, err := writeMsg(st, headReq(a.id.PublicKey(), l.ID())); err != nil {
			t.Fatal(err)
		}
		m, err := readMsg(st, false)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	for i := range MaxStreams - 1 {
		if m := pull(); m.typ != tHead {
			t.Fatalf("pull %d: %+v", i, m)
		}
	}
	if m := pull(); m.typ != tError || m.code != codeBusy {
		t.Fatalf("pull past the slots: %+v, want ERROR busy", m)
	}
	end(w.st)
	waitFor(t, "the watch slot to be free", func() bool { return pull().typ == tHead })
}

// Watch streams are counted apart from the streams that serve pulls, so idle watchers never hold their slots.
func TestIdleWatchersDoNotStarvePulls(t *testing.T) {
	checkGoroutines(t)
	const total = 2
	a := watchPeer(t, ServerOptions{MaxTotalStreams: total}, nil)
	l := ownLog(t, a, 3)
	for range total {
		c := newWatchClient(t, a)
		c.send(named(a, l.ID(), 0))
		c.heads()
	}
	if st, m := dial(t, a, l); m.typ != tHead {
		t.Fatalf("pull with %d idle watchers: %+v", total, m)
	} else {
		end(st)
	}
	over := newWatchClient(t, a)
	over.send(named(a, l.ID(), 0))
	over.ended(codeBusy)
}

func TestWatchRevokedStopsPushes(t *testing.T) {
	checkGoroutines(t)
	var revoked atomic.Bool
	a := watchPeer(t, ServerOptions{}, func(_, _ ed25519.PublicKey, _ kololog.LogID) Access {
		if revoked.Load() {
			return NoAccess
		}
		return Keys
	})
	l := ownLog(t, a, 3)
	c := newWatchClient(t, a)
	c.send(named(a, l.ID(), 0))
	c.sizes(a)
	appendN(t, l, 1)
	if got := c.sizes(a); !slices.Equal(got, []uint64{4}) {
		t.Fatalf("push %v, want [4]", got)
	}
	revoked.Store(true)
	appendN(t, l, 1)
	c.silent(5 * testGap)
}

// The watch stream has no idle deadline: it outlives Timeout with nothing to say.
func TestWatchStreamStaysIdle(t *testing.T) {
	checkGoroutines(t)
	a := watchPeer(t, ServerOptions{}, nil)
	l := ownLog(t, a, 3)
	c := newWatchClient(t, a)
	c.send(named(a, l.ID(), 0))
	c.sizes(a)
	time.Sleep(timeout + time.Second)
	appendN(t, l, 1)
	if got := c.sizes(a); !slices.Equal(got, []uint64{4}) {
		t.Fatalf("push after the idle time %v, want [4]", got)
	}
}

// A request of a type the server does not know, and a WATCH_REQ to a server of v0.1.0, which does not either, get
// ERROR protocol, so a follower can fall back to pulls.
func TestUnknownRequestIsProtocolError(t *testing.T) {
	check := func(t *testing.T, st *kolotransport.Stream, payload []byte) {
		t.Helper()
		if _, err := st.Write(frame(uint32(len(payload)), payload)); err != nil {
			t.Fatal(err)
		}
		if m, err := readMsg(st, false); err != nil || m.typ != tError || m.code != codeProtocol {
			t.Fatalf("answer %+v, %v, want ERROR protocol", m, err)
		}
	}
	t.Run("type 16", func(t *testing.T) {
		checkGoroutines(t)
		a := watchPeer(t, ServerOptions{}, nil)
		conn, _ := connect(t, newPeer(t), a, nil)
		check(t, rawStream(t, conn), []byte{version, tWatch + 1})
	})
	t.Run("WATCH as a request", func(t *testing.T) {
		checkGoroutines(t)
		a := watchPeer(t, ServerOptions{}, nil)
		conn, _ := connect(t, newPeer(t), a, nil)
		check(t, rawStream(t, conn), []byte{version, tWatch, 0})
	})
	t.Run("WATCH_REQ to v0.1.0", func(t *testing.T) {
		checkGoroutines(t)
		addr, pub := oldServer(t)
		id, err := koloid.Generate()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := kolosecure.Dial(testCtx(t), addr, id, pub, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		st := rawStream(t, conn)
		check(t, st, encode(message{typ: tWatchReq, watch: []watchItem{{}}}))
	})
}

// oldServer starts a server built from the v0.1.0 tag of this repository, which serves one connection on 127.0.0.1,
// and returns its address and public key. The test is skipped where the tag or the modules are not at hand.
func oldServer(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOFLAGS=-mod=readonly")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("cannot build a server from v0.1.0: %s %v: %v\n%s", name, args, err, out)
		}
	}
	src := filepath.Join(dir, "src.tar")
	if out, err := exec.Command("git", "archive", "--format=tar", "-o", src, "v0.1.0").CombinedOutput(); err != nil {
		t.Skipf("no tag v0.1.0: %v\n%s", err, out)
	}
	run("tar", "-xf", src)
	if err := os.Mkdir(filepath.Join(dir, "oldserver"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oldserver", "main.go"), []byte(oldServerMain), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "oldserver.bin")
	run("go", "build", "-o", bin, "./oldserver")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		cmd.Wait()
	})
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	addr, key, _ := strings.Cut(strings.TrimSpace(line), " ")
	pub, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	return addr, pub
}

const oldServerMain = `package main

import (
	"context"
	"crypto/ed25519"
	"fmt"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

func main() {
	ctx := context.Background()
	id, err := koloid.Generate()
	if err != nil {
		panic(err)
	}
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", id, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s %x\n", l.Addr(), id.PublicKey())
	c, err := l.Accept(ctx)
	if err != nil {
		panic(err)
	}
	kolosync.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access { return kolosync.Keys }).Serve(ctx, c)
}
`
