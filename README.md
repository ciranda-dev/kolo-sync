# kolo-sync

Replicate a signed kolo-log log from one peer to another, pull only, or fetch some of its entries without a replica.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-sync replicates a signed log by the fetch-and-verify model of [Certificate Transparency 2.0 (RFC 9162)](https://www.rfc-editor.org/info/rfc9162): heads, consistency proofs and inclusion proofs, checked against the owner's signatures only. A `Server` offers the logs the application chooses and asks it which peer may pull or fetch which log. `Pull` opens one stream per log on a connection, checks the peer's signed tree head, fetches the missing entries with consistency proofs, and grows a [kolo-store](https://github.com/ciranda-dev/kolo-store) replica, which verifies every entry before it stores it. Delete markers follow, and so do entry keys for the peers allowed to read them. It works over direct and relayed connections: every call takes a `Conn`, which a [kolo-secure](https://github.com/ciranda-dev/kolo-secure) connection and a kolo-swarm peer link, direct or through a relay, both satisfy.

`Fetch` gets a range of entries on its own, each checked with its inclusion proof against a signed head, for reading part of a log without keeping it. It is pure Go and builds with `CGO_ENABLED=0`.

## Install

```sh
go get github.com/ciranda-dev/kolo-sync
```

## Quick start

Alice writes a log and offers it to bob, who pulls it into a replica and reads it, all on 127.0.0.1:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alice, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	bob, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}

	// Alice writes a log and offers it, with its entry keys, to bob only.
	as := kolostore.New(kolostore.NewMemory())
	defer as.Close()
	l, err := as.Create(alice)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := l.Append([]byte("hello from alice")); err != nil {
		log.Fatal(err)
	}
	srv := kolosync.NewServer(func(peer, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access {
		if peer.Equal(bob.PublicKey()) {
			return kolosync.Keys
		}
		return kolosync.NoAccess
	})
	if err := srv.Offer(l); err != nil {
		log.Fatal(err)
	}
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", alice, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		srv.Serve(ctx, conn)
	}()

	// Bob knows alice's key and the log ID, and keeps a replica in his own store.
	conn, err := kolosecure.Dial(ctx, ln.Addr().String(), bob, alice.PublicKey(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	bs := kolostore.New(kolostore.NewMemory())
	defer bs.Close()
	header, err := kolosync.FetchHeader(ctx, conn, alice.PublicKey(), l.ID())
	if err != nil {
		log.Fatal(err)
	}
	rep, err := bs.OpenReplica(alice.PublicKey(), l.ID(), header)
	if err != nil {
		log.Fatal(err)
	}
	if err := kolosync.Pull(ctx, conn, rep); err != nil {
		log.Fatal(err)
	}
	v, err := rep.Get(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("bob read %q from %d entries\n", v, rep.Len())
}
```

```text
bob read "hello from alice" from 1 entries
```

The same program is in [examples/basic](examples/basic). A real application keeps its stores on disk with `kolostore.OpenPebble`.

## API

A log is named by its owner's public key and its log ID everywhere: in `Offer`, `Withdraw`, `authorize` and on the wire.

| Symbol | What it does |
|---|---|
| `NewServer(authorize)`, `NewServerWith` | A server with no offered logs; `authorize` returns `NoAccess`, `Ciphertext` or `Keys` for each request; `NewServerWith` sets the server-wide limits on streams and answer memory |
| `Server.Offer`, `Server.Withdraw` | Make a kolo-store or kolo-log log or replica available, or stop offering it |
| `Conn` | The connection every call takes: `*kolosecure.Conn`, or `koloswarm.Conn` for a direct or relayed swarm link |
| `Server.Serve(ctx, conn)` | Answer the streams a peer opens on a connection; one per connection |
| `Server.Stats` | Bytes sent and streams being served, over all connections |
| `Pull` | Bring a replica up to date: entries, delete markers and, when the peer gives them, entry keys |
| `PullCiphertext` | `Pull` for a peer that must never hold entry keys, such as a pinning node |
| `PullWith` | `Pull` with `PullOptions`: `NoMarkers` stores no delete marker from the peer, `KeysFrom` starts the key scan at a cursor it returns, `InFlight` sets how far a pull asks ahead (a peer of this version streams entries, so the link stays full on a long round trip), `Meter` gives live statistics, and `PullResult.Stats` says where the time went |
| `FetchHeader`, `FetchHead` | The log's signed header, to open a replica, and the peer's signed head |
| `Fetch` | A range of entries, each checked against a head you trust, without a replica |
| `FetchWithKeys` | `Fetch` with entry keys you hold, to read from a peer that serves ciphertext only |
| `FetchKeys` | The entry keys of a range from a peer with `Keys` access, without the ciphertexts |

Both ends may serve and pull on one connection. `Conn` needs only `RemotePublicKey`, `OpenStream` and `AcceptStream`; on a relayed link as on a direct one, `authorize` gets the key the peer proved in the end-to-end handshake. Entry keys travel only on that end-to-end encrypted connection, never in an error or a log line. Errors are sentinels for `errors.Is`: `ErrNotFound`, `ErrDiverged`, `ErrMarked`, `ErrBehind`, `ErrKeyMismatch`, `ErrInvalid`, `ErrProtocol`, `ErrBusy`, `ErrTooLarge`, `ErrTimeout` and `ErrInvalidArgument`.

## Security notes

- `authorize` runs before the offered logs are looked at, so a missing, an unoffered and an unauthorized log take one path and give the same bytes.
- Every head, entry and proof is checked against the owner's key; a peer cannot make a live entry look deleted without the owner's signed marker.
- Deletion is best effort: a peer that already received an entry key can keep it.
- `Ciphertext` or `Keys` access lets a peer make the server read, prove and send up to 64 MiB of the log for one request of a few bytes, as fast as the peer reads, with no rate bound on its requests. The server holds at most `MaxStreams` streams for a connection and `MaxTotalStreams` and `MaxAnswerBytes` in all, then answers busy; grant access only to peers you trust with that load.

## More

- [Guide](docs/guide.md): every call in detail, errors and design notes.
- [Limits](docs/limits.md): message size, streams, timeouts and memory.
- [Protocol](docs/protocol.md): the wire format and the standards it follows.
- [Security policy](SECURITY.md).

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
