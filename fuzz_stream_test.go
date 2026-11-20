package kolosync

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
)

// FuzzFeed drives the feed of a stream with requests from the bytes: whatever they are, it refuses what is not valid without
// changing, never holds more credit than maxCredit, and stays within its log.
func FuzzFeed(f *testing.F) {
	f.Add([]byte{0, 0, 10, 5, 1, 1, 0, 0, 3, 0, 1, 7})
	f.Add([]byte{1, 0, 0, 0, 0})
	f.Add(binary.LittleEndian.AppendUint64([]byte{0, 0, 9, 9, 1, 2}, 1<<63))
	f.Fuzz(func(t *testing.T, b []byte) {
		var feed feed
		head := uint64(len(b))%17 + 1
		for len(b) >= 6 {
			typ := []uint64{tStreamReq, tCreditReq, tEntriesReq}[b[0]%3]
			m := message{typ: typ, a: uint64(b[1] % 20), size: uint64(b[2] % 20), keys: b[3]&1 == 1, credit: uint64(b[4]) << (b[5] % 40)}
			b = b[6:]
			before := feed
			code := feed.apply(m, head)
			if code != 0 && (code != codeProtocol || feed != before) {
				t.Fatalf("refused %+v with %d and changed %+v to %+v", m, code, before, feed)
			}
			if code == 0 && m.typ == tStreamReq && (!feed.open || feed.next >= feed.size || feed.size > head || feed.credit <= 0) {
				t.Fatalf("accepted %+v for %d entries: %+v", m, head, feed)
			}
			if code == 0 && (m.credit == 0 || m.credit > maxCredit) {
				t.Fatalf("accepted a credit of %d", m.credit)
			}
			if feed.credit > maxCredit || (feed.open && feed.size > head) {
				t.Fatalf("feed %+v for %d entries", feed, head)
			}
			// What pump does with an answer.
			if code == 0 && feed.credit > 0 && feed.next < feed.size {
				k := feed.size - feed.next
				feed.credit -= 1000
				feed.next += max(1, k/2)
				if feed.next > feed.size {
					t.Fatalf("feed past its log: %+v", feed)
				}
			}
		}
	})
}

// fuzzEnv is a log served by a peer that answers a pull with the bytes of the test instead of the real answers.
type fuzzEnv struct {
	id    *koloid.Identity
	log   *kolostore.Log
	st    *kolostore.Store
	conn  *kolosecure.Conn
	data  atomic.Pointer[[]byte]
	ready chan struct{}
}

var (
	fuzzOnce sync.Once
	fuzzEnvV *fuzzEnv
)

// theFuzzEnv builds the environment once, because setting a connection up for each input would make the fuzz target slow; it is
// never torn down, which is what the end of the process does.
func theFuzzEnv(f testing.TB) *fuzzEnv {
	fuzzOnce.Do(func() {
		ctx := context.Background()
		owner, err := koloid.Generate()
		if err != nil {
			f.Fatal(err)
		}
		puller, err := koloid.Generate()
		if err != nil {
			f.Fatal(err)
		}
		log, err := kolostore.New(kolostore.NewMemory()).Create(owner)
		if err != nil {
			f.Fatal(err)
		}
		for i := range fuzzEntries {
			if _, err := log.Append(bytes.Repeat([]byte{byte(i)}, 3000)); err != nil {
				f.Fatal(err)
			}
		}
		ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", owner, nil)
		if err != nil {
			f.Fatal(err)
		}
		env := &fuzzEnv{id: owner, log: log, st: kolostore.New(kolostore.NewMemory()), ready: make(chan struct{})}
		go func() {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			for {
				st, err := c.AcceptStream(ctx)
				if err != nil {
					return
				}
				go func() {
					defer end(st)
					if _, err := readMsg(st, true); err != nil {
						return
					}
					h, _ := log.Head()
					if _, err := writeMsg(st, message{typ: tHead, head: h.Encode(), header: log.Header().Encode()}); err != nil {
						return
					}
					if _, err := readMsg(st, true); err != nil {
						return
					}
					if d := env.data.Load(); d != nil {
						st.Write(*d)
					}
				}()
			}
		}()
		env.conn, err = kolosecure.Dial(ctx, ln.Addr().String(), puller, owner.PublicKey(), nil)
		if err != nil {
			f.Fatal(err)
		}
		fuzzEnvV = env
	})
	return fuzzEnvV
}

const fuzzEntries = 12

// FuzzStreamAnswers pulls from a peer whose answers to STREAM_REQ are the bytes of the test, and checks that the pull never panics or hangs, ends with
// one of the errors of the package, and stores only entries the honest log holds.
func FuzzStreamAnswers(f *testing.F) {
	env := theFuzzEnv(f)
	honest := func() []byte {
		var out []byte
		for next := uint64(0); next < fuzzEntries; {
			resp, code := entries(env.log, true, next, fuzzEntries-1, 0)
			if code != 0 {
				f.Fatal(code)
			}
			out = append(out, wire(resp)...)
			next += uint64(len(resp.entries))
			if next < fuzzEntries {
				pr, _ := proof(env.log, next, fuzzEntries)
				out = append(out, wire(pr)...)
			}
		}
		return out
	}()
	f.Add(honest)
	f.Add(honest[:len(honest)/2])
	f.Add([]byte{})
	f.Add(wire(message{typ: tError, code: codeProtocol}))
	f.Add(wire(message{typ: tError, code: codeBusy}))
	f.Add(append(wire(message{typ: tProof, proof: []byte{1}}), honest...))
	f.Add(frame(MaxMessageSize+1, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		env.data.Store(&data)
		h := env.log.Header()
		r, err := env.st.OpenReplica(h.LogKey, env.log.ID(), h.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, err = PullWith(ctx, env.conn, r, &PullOptions{InFlight: 1 + int(binary.LittleEndian.Uint16(append(data, 0, 0))%MaxInFlight)})
		// The peer ends the stream after its bytes, so a pull that reads them all fails at its STATE request.
		if err == nil && r.Len() != fuzzEntries {
			t.Fatalf("Pull succeeded with %d of %d entries", r.Len(), fuzzEntries)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "kolosync:") {
			t.Fatalf("error %v does not come from the package", err)
		}
		for i := range r.Len() {
			got, err := r.Get(i)
			want, _ := env.log.Get(i)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("entry %d: %v", i, err)
			}
		}
	})
}
