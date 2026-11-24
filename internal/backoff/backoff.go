// Package backoff computes retry delays: exponential growth, capped, with full jitter above a floor.
package backoff

import (
	"math/rand/v2"
	"time"
)

// Delay returns the wait after n consecutive failures: lo plus a uniform draw from [0, min(hi, lo·2^n) - lo).
// rnd(k) must return a value in [0, k); nil uses math/rand/v2.
func Delay(n int, lo, hi time.Duration, rnd func(int64) int64) time.Duration {
	if rnd == nil {
		rnd = rand.Int64N
	}
	ceil := lo
	for i := 0; i < n && ceil < hi; i++ {
		ceil *= 2
	}
	ceil = min(ceil, hi)
	if ceil <= lo {
		return lo
	}
	return lo + time.Duration(rnd(int64(ceil-lo)))
}
