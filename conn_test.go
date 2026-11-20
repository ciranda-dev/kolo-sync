package kolosync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

var (
	_ Conn = (*kolosecure.Conn)(nil)
	_ Conn = (*relayed)(nil)
)

// relayed is a Conn that is not a *kolosecure.Conn: like a relayed link, it carries an end-to-end
// kolo-secure connection inside, so a type assertion in kolosync would refuse it.
type relayed struct{ ic *kolosecure.Conn }

func (r *relayed) RemotePublicKey() ed25519.PublicKey { return r.ic.RemotePublicKey() }

func (r *relayed) OpenStream(ctx context.Context) (*kolotransport.Stream, error) {
	return r.ic.OpenStream(ctx)
}

func (r *relayed) AcceptStream(ctx context.Context) (*kolotransport.Stream, error) {
	return r.ic.AcceptStream(ctx)
}

// recorder is an authorize that gives Keys to allowed only and records every peer key it is asked about.
type recorder struct {
	allowed ed25519.PublicKey
	mu      sync.Mutex
	seen    [][]byte
}

func (r *recorder) authorize(peer, _ ed25519.PublicKey, _ kololog.LogID) Access {
	r.mu.Lock()
	r.seen = append(r.seen, bytes.Clone(peer))
	r.mu.Unlock()
	if bytes.Equal(peer, r.allowed) {
		return Keys
	}
	return NoAccess
}

func (r *recorder) keys() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

// onlyKey reports whether keys is not empty and holds only want.
func onlyKey(keys [][]byte, want ed25519.PublicKey) bool {
	for _, k := range keys {
		if !bytes.Equal(k, want) {
			return false
		}
	}
	return len(keys) > 0
}

func TestConnConformance(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	ab, ba := connect(t, a, b, nil)
	ra, rb := connectRelayed(t, a, b)
	for name, c := range map[string]struct {
		conn Conn
		want ed25519.PublicKey
	}{
		"direct a":  {ab, b.id.PublicKey()},
		"direct b":  {ba, a.id.PublicKey()},
		"relayed a": {ra, b.id.PublicKey()},
		"relayed b": {rb, a.id.PublicKey()},
	} {
		if got := c.conn.RemotePublicKey(); !bytes.Equal(got, c.want) {
			t.Errorf("%s: RemotePublicKey is not the peer's key", name)
		}
	}
}

// A Conn that is not a *kolosecure.Conn carries every call, and the server authorizes the key it proves.
func TestSyncOverRelayedConn(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	rec := &recorder{allowed: b.id.PublicKey()}
	a.srv = NewServer(rec.authorize)
	l := ownLog(t, a, 50)
	ba, _ := connectRelayed(t, b, a)
	ctx := testCtx(t)

	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	if err := Pull(ctx, ba, r); err != nil {
		t.Fatal(err)
	}
	sameEntries(t, r, l)
	appendN(t, l, 10)
	if res, err := PullWith(ctx, ba, r, nil); err != nil || res.KeysFrom != 60 {
		t.Fatalf("PullWith = %+v, %v", res, err)
	}
	sameEntries(t, r, l)

	h, err := FetchHead(ctx, ba, a.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	want := trusted(t, l)
	if !bytes.Equal(h.Head().Encode(), want.Head().Encode()) {
		t.Fatal("FetchHead differs from the owner's head")
	}
	fs, err := Fetch(ctx, ba, h, 0, 59)
	if err != nil || len(fs) != 60 {
		t.Fatalf("Fetch = %d values, %v", len(fs), err)
	}
	keys, err := FetchKeys(ctx, ba, h, 0, 59)
	if err != nil || len(keys) != 60 {
		t.Fatalf("FetchKeys = %d keys, %v", len(keys), err)
	}
	for i := range uint64(60) {
		v, _ := l.Get(i)
		k, _ := l.Key(i)
		if fs[i].Err != nil || !bytes.Equal(fs[i].Data, v) || !bytes.Equal(keys[i], k) {
			t.Fatalf("entry %d differs", i)
		}
	}
	if !onlyKey(rec.keys(), b.id.PublicKey()) {
		t.Fatal("authorize was asked about another key than the puller's")
	}
}

// A peer that proves a key the server does not authorize gets the same answers on a relayed Conn as on a
// direct one, and authorize sees that peer's proved key on both.
func TestWrongPeerKeyOnRelayedConn(t *testing.T) {
	checkGoroutines(t)
	a, b, c := newPeer(t), newPeer(t), newPeer(t)
	rec := &recorder{allowed: b.id.PublicKey()}
	a.srv = NewServer(rec.authorize)
	l := ownLog(t, a, 5)
	h := trusted(t, l)
	owner, id := a.id.PublicKey(), l.ID()
	ctx := testCtx(t)

	ba, _ := connectRelayed(t, b, a)
	header, err := FetchHeader(ctx, ba, owner, id)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.st.OpenReplica(owner, id, header)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })

	calls := func(conn Conn) []error {
		return []error{
			second(FetchHeader(ctx, conn, owner, id)),
			second(FetchHead(ctx, conn, owner, id)),
			second(Fetch(ctx, conn, h, 0, 4)),
			second(FetchKeys(ctx, conn, h, 0, 4)),
			Pull(ctx, conn, r),
			PullCiphertext(ctx, conn, r),
		}
	}
	ca, _ := connect(t, c, a, nil)
	cr, _ := connectRelayed(t, c, a)
	start := len(rec.keys())
	direct := calls(ca)
	mid := len(rec.keys())
	relay := calls(cr)
	seen := rec.keys()
	for i := range direct {
		if !errors.Is(direct[i], ErrNotFound) || !errors.Is(relay[i], ErrNotFound) || direct[i].Error() != relay[i].Error() {
			t.Errorf("call %d: direct %v, relayed %v; want ErrNotFound on both", i, direct[i], relay[i])
		}
	}
	if !onlyKey(seen[start:mid], c.id.PublicKey()) || !onlyKey(seen[mid:], c.id.PublicKey()) {
		t.Fatal("authorize did not see the wrong peer's proved key on both connections")
	}
	if r.Len() != 0 {
		t.Fatalf("the refused peer's replica holds %d entries", r.Len())
	}
}

// Every entry point takes a nil Conn, or a Conn holding a nil pointer, as ErrInvalidArgument.
func TestNilConn(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := ownLog(t, a, 3)
	ba, _ := connect(t, b, a, nil)
	r := replica(t, b, ba, a.id.PublicKey(), l.ID())
	h := trusted(t, l)
	owner, id := a.id.PublicKey(), l.ID()
	ctx := testCtx(t)
	calls := map[string]func(Conn) error{
		"Pull":           func(c Conn) error { return Pull(ctx, c, r) },
		"PullWith":       func(c Conn) error { return second(PullWith(ctx, c, r, nil)) },
		"PullCiphertext": func(c Conn) error { return PullCiphertext(ctx, c, r) },
		"FetchHeader":    func(c Conn) error { return second(FetchHeader(ctx, c, owner, id)) },
		"FetchHead":      func(c Conn) error { return second(FetchHead(ctx, c, owner, id)) },
		"Fetch":          func(c Conn) error { return second(Fetch(ctx, c, h, 0, 2)) },
		"FetchWithKeys":  func(c Conn) error { return second(FetchWithKeys(ctx, c, h, 0, 2, nil)) },
		"FetchKeys":      func(c Conn) error { return second(FetchKeys(ctx, c, h, 0, 2)) },
		"Serve":          func(c Conn) error { return a.srv.Serve(ctx, c) },
	}
	conns := map[string]Conn{
		"nil":                  nil,
		"nil *kolosecure.Conn": (*kolosecure.Conn)(nil),
		"nil *relayed":         (*relayed)(nil),
	}
	for cn, conn := range conns {
		for name, call := range calls {
			err := func() (err error) {
				defer func() {
					if p := recover(); p != nil {
						err = errors.New("panic")
					}
				}()
				return call(conn)
			}()
			if !errors.Is(err, ErrInvalidArgument) {
				t.Errorf("%s with %s: %v, want ErrInvalidArgument", name, cn, err)
			}
		}
	}
}

var errClosed = errors.New("closed")

// keyConn is a Conn whose RemotePublicKey is key and whose streams always fail.
type keyConn struct {
	key     ed25519.PublicKey
	accepts atomic.Int32
}

func (k *keyConn) RemotePublicKey() ed25519.PublicKey { return k.key }

func (k *keyConn) OpenStream(context.Context) (*kolotransport.Stream, error) { return nil, errClosed }

func (k *keyConn) AcceptStream(context.Context) (*kolotransport.Stream, error) {
	k.accepts.Add(1)
	return nil, errClosed
}

// Serve refuses a Conn whose peer key is not an Ed25519 public key before it accepts a stream.
func TestServeMalformedPeerKey(t *testing.T) {
	srv := NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return Keys })
	for name, key := range map[string]ed25519.PublicKey{
		"nil":   nil,
		"short": make([]byte, ed25519.PublicKeySize-1),
		"long":  make([]byte, ed25519.PublicKeySize+1),
	} {
		c := &keyConn{key: key}
		if err := srv.Serve(testCtx(t), c); !errors.Is(err, ErrInvalidArgument) || c.accepts.Load() != 0 {
			t.Errorf("%s key: Serve = %v after %d accepts, want ErrInvalidArgument before any", name, err, c.accepts.Load())
		}
	}
	c := &keyConn{key: make([]byte, ed25519.PublicKeySize)}
	if err := srv.Serve(testCtx(t), c); errors.Is(err, ErrInvalidArgument) || c.accepts.Load() != 1 {
		t.Fatalf("valid key: Serve = %v after %d accepts", err, c.accepts.Load())
	}
}
