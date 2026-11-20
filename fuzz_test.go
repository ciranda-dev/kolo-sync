package kolosync

import (
	"bytes"
	"context"
	"errors"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
)

func FuzzDecode(f *testing.F) {
	for _, m := range samples() {
		f.Add(encode(m), request(m.typ))
	}
	f.Fuzz(func(t *testing.T, b []byte, requests bool) {
		m, err := decode(b, requests)
		if err != nil {
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("error %v is not ErrProtocol", err)
			}
			return
		}
		if f := frameOf(m); cap(f) != 4+bound(m) {
			t.Fatalf("frame of %x grew past its presized slice", b)
		}
		if again := encode(m); !bytes.Equal(again, b) {
			t.Fatalf("not canonical: %x re-encodes as %x", b, again)
		}
	})
}

func FuzzReadFrame(f *testing.F) {
	for _, m := range samples() {
		f.Add(wire(m), request(m.typ))
	}
	f.Add(frame(MaxMessageSize+1, nil), false)
	f.Fuzz(func(t *testing.T, b []byte, requests bool) {
		m, err := readFrame(bytes.NewReader(b), requests, nil)
		if err != nil {
			if !errors.Is(err, ErrProtocol) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("error %v is not ErrProtocol or ErrTooLarge", err)
			}
			return
		}
		if w := wire(m); !bytes.HasPrefix(b, w) {
			t.Fatalf("frame %x re-encodes as %x", b, w)
		}
	})
}

// FuzzEntriesCount checks that the count read from the start of a payload is the number of entries decode finds.
func FuzzEntriesCount(f *testing.F) {
	for _, m := range samples() {
		f.Add(encode(m))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		n, ok := entriesCount(b[:min(len(b), peekSize)])
		m, err := decode(b, false)
		if err != nil || m.typ != tEntries {
			return
		}
		if !ok || n != uint64(len(m.entries)) {
			t.Fatalf("entriesCount of %x = %d, %v; decode finds %d entries", b, n, ok, len(m.entries))
		}
	})
}

// FuzzOpened checks a FETCH answer from a hostile peer, opened with no held keys (held 0), the right ones (1)
// or another entry's (2): it never yields a value the log does not hold.
func FuzzOpened(f *testing.F) {
	id, err := koloid.Generate()
	if err != nil {
		f.Fatal(err)
	}
	l, err := kololog.New(id, kololog.NewMemory())
	if err != nil {
		f.Fatal(err)
	}
	defer l.Close()
	appendN(f, l, 3)
	if err := l.Delete(1); err != nil {
		f.Fatal(err)
	}
	head, err := l.Head()
	if err != nil {
		f.Fatal(err)
	}
	h, err := kololog.VerifyHead(id.PublicKey(), l.ID(), head)
	if err != nil {
		f.Fatal(err)
	}
	m, code := entries(l, true, 0, 2, 3)
	if code != 0 {
		f.Fatalf("entries: code %d", code)
	}
	for held := range byte(3) {
		f.Add(encode(m), held)
	}
	m.entries[0].Key, m.entries[2].Key = nil, nil
	for held := range byte(3) {
		f.Add(encode(m), held)
	}
	f.Fuzz(func(t *testing.T, b []byte, held byte) {
		m, err := decode(b, false)
		if err != nil || m.typ != tFetch {
			return
		}
		defer wipe(m)
		var keys func(uint64) (kololog.EntryKey, error)
		switch held {
		case 1:
			keys = l.Key
		case 2:
			keys = func(i uint64) (kololog.EntryKey, error) { return l.Key(2 - i) }
		}
		out, pending, err := opened(nil, nil, h, m, 0, 2, keys != nil)
		if err == nil {
			out, err = openAllHeld(context.Background(), out, pending, h, keys)
		}
		if err != nil {
			if held == 1 && errors.Is(err, ErrKeyMismatch) {
				t.Fatalf("the owner's keys do not match: %v", err)
			}
			if !errors.Is(err, ErrProtocol) && !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v is not ErrProtocol or ErrInvalid", err)
			}
			return
		}
		for j, x := range out {
			want, werr := l.Get(uint64(j))
			switch {
			case x.Index != uint64(j):
				t.Fatalf("result %d has index %d", j, x.Index)
			case x.Err == nil && (werr != nil || !bytes.Equal(x.Data, want)):
				t.Fatalf("entry %d opened to %q, the log holds %q (%v)", j, x.Data, want, werr)
			case errors.Is(x.Err, kololog.ErrDeleted) != errors.Is(werr, kololog.ErrDeleted):
				t.Fatalf("entry %d: %v, the log says %v", j, x.Err, werr)
			case held == 1 && errors.Is(x.Err, ErrKeyMismatch):
				t.Fatalf("entry %d: the owner's key does not match: %v", j, x.Err)
			case x.Err != nil && !errors.Is(x.Err, kololog.ErrDeleted) && !errors.Is(x.Err, kololog.ErrKeyUnavailable) && !errors.Is(x.Err, ErrKeyMismatch):
				t.Fatalf("entry %d: unexpected %v", j, x.Err)
			}
		}
	})
}
