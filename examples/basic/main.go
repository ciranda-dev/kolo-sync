// Command basic syncs a log between two peers on loopback: alice writes and offers it, bob pulls and reads it.
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
