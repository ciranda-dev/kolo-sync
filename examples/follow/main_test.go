package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := run(ctx, &out, filepath.Join(t.TempDir(), "bob")); err != nil {
		t.Fatal(err)
	}
	want := "bob has 2 entries\nbob has 3 entries\nbob restarted with 3 entries\nbob has 5 entries\n"
	if out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
}
