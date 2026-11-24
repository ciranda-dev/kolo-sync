// Command follow keeps a replica up to date with a Follower: bob follows alice's log, stops, restarts from his
// directory and goes on, all on loopback.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

func main() {
	dir, err := os.MkdirTemp("", "kolo-sync-follow-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := run(ctx, os.Stdout, filepath.Join(dir, "bob")); err != nil {
		log.Fatal(err)
	}
}

// run writes what happens to w and keeps bob's Pebble store in dir, which is empty or does not exist.
func run(ctx context.Context, w io.Writer, dir string) error {
	alice, err := koloid.Generate()
	if err != nil {
		return err
	}
	bob, err := koloid.Generate()
	if err != nil {
		return err
	}

	// Alice writes a log and offers it to bob.
	as := kolostore.New(kolostore.NewMemory())
	defer as.Close()
	l, err := as.Create(alice)
	if err != nil {
		return err
	}
	appendN := func(n int) error {
		for range n {
			if _, err := l.Append([]byte("entry")); err != nil {
				return err
			}
		}
		return nil
	}
	if err := appendN(2); err != nil {
		return err
	}
	srv := kolosync.NewServer(func(peer, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access {
		if peer.Equal(bob.PublicKey()) {
			return kolosync.Keys
		}
		return kolosync.NoAccess
	})
	if err := srv.Offer(l); err != nil {
		return err
	}
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", alice, nil)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go srv.Serve(ctx, conn)
		}
	}()

	// Bob follows the log on the connection, with a replica in a Pebble directory.
	store := func() (*kolostore.Store, error) {
		b, err := kolostore.OpenPebble(dir)
		if err != nil {
			return nil, err
		}
		return kolostore.New(b), nil
	}
	bs, err := store()
	if err != nil {
		return err
	}
	conn, err := kolosecure.Dial(ctx, ln.Addr().String(), bob, alice.PublicKey(), nil)
	if err != nil {
		return err
	}
	header, err := kolosync.FetchHeader(ctx, conn, alice.PublicKey(), l.ID())
	if err != nil {
		return err
	}
	rep, err := bs.OpenReplica(alice.PublicKey(), l.ID(), header)
	if err != nil {
		return err
	}
	f, err := kolosync.NewFollower(nil)
	if err != nil {
		return err
	}
	if err := f.Add(rep); err != nil {
		return err
	}
	stop := follow(ctx, f, conn)
	if err := grow(ctx, w, f, rep, 2); err != nil {
		return err
	}

	// An entry that alice appends while bob follows arrives without bob asking.
	if err := appendN(1); err != nil {
		return err
	}
	if err := grow(ctx, w, f, rep, 3); err != nil {
		return err
	}

	// Bob stops, alice goes on, and bob starts again from the replicas in his directory.
	stop()
	f.Close()
	conn.Close()
	if err := bs.Close(); err != nil {
		return err
	}
	if err := appendN(2); err != nil {
		return err
	}
	if bs, err = store(); err != nil {
		return err
	}
	defer bs.Close()
	ids, err := bs.List()
	if err != nil {
		return err
	}
	if conn, err = kolosecure.Dial(ctx, ln.Addr().String(), bob, alice.PublicKey(), nil); err != nil {
		return err
	}
	defer conn.Close()
	if f, err = kolosync.NewFollower(nil); err != nil {
		return err
	}
	defer f.Close()
	for _, id := range ids {
		owner, _, err := bs.Owner(id)
		if err != nil {
			return err
		}
		if rep, err = bs.OpenReplica(owner, id, nil); err != nil {
			return err
		}
		if err := f.Add(rep); err != nil {
			return err
		}
	}
	fmt.Fprintf(w, "bob restarted with %d entries\n", rep.Len())
	defer follow(ctx, f, conn)()
	return grow(ctx, w, f, rep, 5)
}

// follow runs f.Follow on conn and returns the function that stops it.
func follow(ctx context.Context, f *kolosync.Follower, conn kolosync.Conn) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.Follow(ctx, conn)
	}()
	return func() {
		cancel()
		<-done
	}
}

// grow waits for f to report that rep reached want entries.
func grow(ctx context.Context, w io.Writer, f *kolosync.Follower, rep *kolostore.Replica, want uint64) error {
	for rep.Len() < want {
		ev, err := f.Next(ctx)
		if err != nil {
			return err
		}
		if ev.Kind == kolosync.FollowPullFailed {
			return ev.Err
		}
	}
	fmt.Fprintf(w, "bob has %d entries\n", rep.Len())
	return nil
}
