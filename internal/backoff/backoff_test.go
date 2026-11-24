package backoff

import (
	"testing"
	"time"
)

func TestBounds(t *testing.T) {
	min, max := time.Second, 5*time.Minute
	low := func(int64) int64 { return 0 }
	for n := 1; n <= 40; n++ {
		ceil := min << n
		if n > 20 || ceil > max {
			ceil = max
		}
		high := func(k int64) int64 { return k - 1 }
		if got := Delay(n, min, max, low); got != min {
			t.Fatalf("n=%d lowest = %v, want the floor %v", n, got, min)
		}
		if got := Delay(n, min, max, high); got != ceil-1 {
			t.Fatalf("n=%d highest = %v, want just below %v", n, got, ceil)
		}
	}
}

func TestCapReached(t *testing.T) {
	high := func(k int64) int64 { return k - 1 }
	if got := Delay(9, time.Second, 5*time.Minute, high); got != 5*time.Minute-1 {
		t.Fatalf("n=9 highest = %v, want the cap", got)
	}
	if got := Delay(8, time.Second, 5*time.Minute, high); got != 256*time.Second-1 {
		t.Fatalf("n=8 highest = %v, want 256s", got)
	}
}

func TestJitterSpreads(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 200 {
		d := Delay(6, 50*time.Millisecond, time.Minute, nil)
		if d < 50*time.Millisecond || d >= 3200*time.Millisecond {
			t.Fatalf("delay %v out of [50ms, 3.2s)", d)
		}
		seen[d] = true
	}
	if len(seen) < 100 {
		t.Fatalf("only %d distinct delays in 200 draws", len(seen))
	}
}

func TestDegenerate(t *testing.T) {
	if got := Delay(0, time.Second, time.Minute, nil); got != time.Second {
		t.Fatalf("n=0: %v", got)
	}
	if got := Delay(3, time.Second, time.Second, nil); got != time.Second {
		t.Fatalf("min == max: %v", got)
	}
	if got := Delay(1<<30, time.Millisecond, time.Hour, func(k int64) int64 { return k - 1 }); got != time.Hour-1 {
		t.Fatalf("huge n: %v", got)
	}
}
