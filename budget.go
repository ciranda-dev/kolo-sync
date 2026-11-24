package kolosync

import (
	"crypto/ed25519"
	"sync"
	"time"
)

// budgets keeps a token bucket of bytes for each peer key. A bucket that has refilled to the burst is forgotten, since
// a new peer starts with a full one, so the map holds only the peers that took bytes within the last burst / rate.
type budgets struct {
	rate, burst float64 // bytes a second, bytes
	now         func() time.Time
	mu          sync.Mutex
	m           map[[ed25519.PublicKeySize]byte]*bucket
	swept       time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newBudgets(rate, burst int64) *budgets {
	return &budgets{rate: float64(rate), burst: float64(burst), now: time.Now, m: make(map[[ed25519.PublicKeySize]byte]*bucket)}
}

// bucketOf returns the bucket of peer, refilled up to now; the caller holds mu.
func (b *budgets) bucketOf(peer ed25519.PublicKey, now time.Time) *bucket {
	if now.Sub(b.swept) >= time.Duration(b.burst/b.rate*float64(time.Second)) {
		for k, bk := range b.m {
			if bk.tokens+now.Sub(bk.at).Seconds()*b.rate >= b.burst {
				delete(b.m, k)
			}
		}
		b.swept = now
	}
	k := [ed25519.PublicKeySize]byte(peer)
	bk := b.m[k]
	if bk == nil {
		bk = &bucket{tokens: b.burst, at: now}
		b.m[k] = bk
	}
	bk.tokens = min(b.burst, bk.tokens+now.Sub(bk.at).Seconds()*b.rate)
	bk.at = now
	return bk
}

// take removes n bytes from the bucket of peer, or none and false if it holds fewer.
func (b *budgets) take(peer ed25519.PublicKey, n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	bk := b.bucketOf(peer, b.now())
	if bk.tokens < float64(n) {
		return false
	}
	bk.tokens -= float64(n)
	return true
}

// give puts n bytes back in the bucket of peer.
func (b *budgets) give(peer ed25519.PublicKey, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	bk := b.bucketOf(peer, b.now())
	bk.tokens = min(b.burst, bk.tokens+float64(n))
}
