package kolosync_test

import (
	"context"
	"errors"

	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// pullLive pulls rep from the first peer that serves every entry it lacks as a live entry, up to the head
// of the peer that served a deleted one, and returns the key cursor to keep for the next pull.
func pullLive(ctx context.Context, peers []kolosync.Conn, rep *kolostore.Replica, keysFrom uint64) (uint64, error) {
	err := kolosync.ErrNotFound
	for _, conn := range peers {
		var res kolosync.PullResult
		res, err = kolosync.PullWith(ctx, conn, rep, &kolosync.PullOptions{NoMarkers: true, KeysFrom: keysFrom})
		if err == nil {
			return res.KeysFrom, nil
		}
		if !errors.Is(err, kolosync.ErrMarked) && !errors.Is(err, kolosync.ErrBehind) {
			return keysFrom, err
		}
		// rep holds the entries before the deleted one; the next peer goes on from rep.Len().
	}
	return keysFrom, err
}

// The guide shows pullLive; this example only keeps it compiling.
func ExamplePullWith() {
	_ = pullLive
}
