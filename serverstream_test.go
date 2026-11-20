package kolosync

import (
	"crypto/ed25519"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// streamClient is a raw client of a Server: it has sent HEAD_REQ and read HEAD.
type streamClient struct {
	t    *testing.T
	st   *kolotransport.Stream
	size uint64
}

func newStreamClient(t *testing.T, a, b *peer, l interface {
	ID() kololog.LogID
	Len() uint64
}) *streamClient {
	t.Helper()
	conn, _ := connect(t, b, a, nil)
	st := rawStream(t, conn)
	if _, err := writeMsg(st, headReq(a.id.PublicKey(), l.ID())); err != nil {
		t.Fatal(err)
	}
	if m, err := readMsg(st, false); err != nil || m.typ != tHead {
		t.Fatalf("HEAD: %+v, %v", m, err)
	}
	return &streamClient{t: t, st: st, size: l.Len()}
}

func (c *streamClient) send(m message) {
	c.t.Helper()
	if _, err := writeMsg(c.st, m); err != nil {
		c.t.Fatal(err)
	}
}

func (c *streamClient) read() message {
	c.t.Helper()
	m, err := readMsg(c.st, false)
	if err != nil {
		c.t.Fatal(err)
	}
	return m
}

// answer reads an ENTRIES answer, and the PROOF after it unless it reaches the end of the log, and returns the entries'
// count and the bytes the credit pays for. next is where the answer must start.
func (c *streamClient) answer(next uint64) (count, cost int) {
	c.t.Helper()
	c.st.SetReadDeadline(time.Now().Add(timeout))
	b, err := readRaw(c.st)
	if err != nil {
		c.t.Fatal(err)
	}
	m, err := decode(b, false)
	if err != nil || m.typ != tEntries || len(m.entries) == 0 {
		c.t.Fatalf("answer %+v, %v, want ENTRIES", m, err)
	}
	count, cost = len(m.entries), len(b)
	if next+uint64(count) < c.size {
		if p := c.read(); p.typ != tProof {
			c.t.Fatalf("after ENTRIES: %+v, want PROOF", p)
		}
	}
	return count, cost
}

func (c *streamClient) silent() {
	c.t.Helper()
	c.st.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var b [1]byte
	if n, err := c.st.Read(b[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		c.t.Fatalf("read %d bytes, %v: the server sent more than the credit pays for", n, err)
	}
}

// ended checks that the server sent ERROR with code and then ended the stream.
func (c *streamClient) ended(code uint64) {
	c.t.Helper()
	if m := c.read(); m.typ != tError || m.code != code {
		c.t.Fatalf("answer %+v, want ERROR %d", m, code)
	}
	if m, err := readMsg(c.st, false); err == nil {
		c.t.Fatalf("the stream went on after the error: %+v", m)
	}
}

// The server sends ENTRIES answers, each followed by the proof of its end unless it ends the log, while the credit lasts,
// counts what each costs in the length of the message, and goes on when more credit comes.
func TestServeStreamCredit(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := sizedLog(t, a, repeat(600<<10, 8)) // one entry to an answer
	a.srv.Offer(l)
	c := newStreamClient(t, a, b, l)
	c.send(message{typ: tStreamReq, a: 0, size: c.size, keys: true, credit: 100 << 10})
	n, cost := c.answer(0)
	if n != 1 || cost < 600<<10 {
		t.Fatalf("first answer: %d entries, %d bytes", n, cost)
	}
	c.silent() // 100 KiB of credit paid for one answer, which left it below 0
	// The credit is now 100 KiB - cost, a debt; 2 MiB leaves 2 MiB - (cost - 100 KiB), which pays for answers until it is used up.
	c.send(message{typ: tCreditReq, credit: 2 << 20})
	left := 2<<20 - (cost - 100<<10)
	next := uint64(1)
	for left > 0 {
		n, cost := c.answer(next)
		next += uint64(n)
		left -= cost
	}
	c.silent()
	if next < 3 {
		t.Fatalf("the credit paid for %d more answers, want 2 or more", next-1)
	}
	// The stream still answers calls, and a stream request starts a new feed.
	c.send(message{typ: tProofReq, a: 3, b: c.size})
	if m := c.read(); m.typ != tProof {
		t.Fatalf("PROOF_REQ: %+v", m)
	}
	c.send(message{typ: tStreamReq, a: 6, size: c.size, keys: true, credit: 10 << 20})
	for next = 6; next < c.size; {
		n, _ := c.answer(next)
		next += uint64(n)
	}
	// Credit for a log that is at its end is for nothing, and the next answer on the stream is the next request's.
	c.send(message{typ: tCreditReq, credit: 1 << 20})
	c.send(message{typ: tCreditReq, credit: 1 << 20})
	c.send(message{typ: tStateReq, a: 0, b: c.size - 1})
	if m := c.read(); m.typ != tState {
		t.Fatalf("after credit at the end: %+v, want STATE", m)
	}
}

// A stream request of a log that holds 8 entries is answered by the entries, in order, until its end, whatever the credit.
func TestServeStreamWholeLog(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := sizedLog(t, a, mixedSizes(50))
	a.srv.Offer(l)
	c := newStreamClient(t, a, b, l)
	c.send(message{typ: tStreamReq, a: 5, size: c.size, keys: true, credit: maxCredit})
	for next := uint64(5); next < c.size; {
		n, _ := c.answer(next)
		next += uint64(n)
	}
	c.silent()
}

func TestServeStreamRejects(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first *message // a valid STREAM_REQ sent first, whose answers are read
		bad   func(size uint64) message
	}{
		{"CREDIT_REQ before STREAM_REQ", nil, func(uint64) message { return message{typ: tCreditReq, credit: 1} }},
		{"start at the end", nil, func(s uint64) message { return message{typ: tStreamReq, a: s, size: s, credit: 1} }},
		{"start past the end", nil, func(s uint64) message { return message{typ: tStreamReq, a: s + 1, size: s, credit: 1} }},
		{"size past the head", nil, func(s uint64) message { return message{typ: tStreamReq, a: 0, size: s + 1, credit: 1} }},
		{"size 0", nil, func(uint64) message { return message{typ: tStreamReq, credit: 1} }},
		{"credit 0", nil, func(s uint64) message { return message{typ: tStreamReq, a: 0, size: s} }},
		{"credit past the most", nil, func(s uint64) message { return message{typ: tStreamReq, size: s, credit: maxCredit + 1} }},
		{"credit that wraps", nil, func(s uint64) message { return message{typ: tStreamReq, size: s, credit: 1 << 63} }},
		{"CREDIT_REQ of 0", &message{typ: tStreamReq, size: 6, credit: 1}, func(uint64) message { return message{typ: tCreditReq} }},
		{"CREDIT_REQ past the most", &message{typ: tStreamReq, size: 6, credit: 1}, func(uint64) message { return message{typ: tCreditReq, credit: maxCredit + 1} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			a, b := newPeer(t), newPeer(t)
			l := sizedLog(t, a, repeat(2<<10, 6))
			a.srv.Offer(l)
			c := newStreamClient(t, a, b, l)
			if tc.first != nil {
				c.send(*tc.first)
				for next := uint64(0); next < 1; {
					n, _ := c.answer(next)
					next += uint64(n)
				}
			}
			c.send(tc.bad(c.size))
			c.ended(codeProtocol)
		})
	}
}

// A peer with Ciphertext access gets no keys on a stream, whatever it asks, and one with Keys gets them only if it asks.
func TestServeStreamKeys(t *testing.T) {
	for _, tc := range []struct {
		access Access
		keys   bool
		want   bool
	}{{Ciphertext, true, false}, {Keys, false, false}, {Keys, true, true}} {
		checkGoroutines(t)
		a, b := newPeer(t), newPeer(t)
		a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access { return tc.access })
		l := sizedLog(t, a, repeat(2<<10, 4))
		a.srv.Offer(l)
		c := newStreamClient(t, a, b, l)
		c.send(message{typ: tStreamReq, size: c.size, keys: tc.keys, credit: 10 << 20})
		c.st.SetReadDeadline(time.Now().Add(timeout))
		raw, err := readRaw(c.st)
		if err != nil {
			t.Fatal(err)
		}
		m, err := decode(raw, false)
		if err != nil || len(m.entries) == 0 {
			t.Fatalf("%+v, %v", m, err)
		}
		for _, e := range m.entries {
			if (len(e.Key) != 0) != tc.want {
				t.Fatalf("access %v keys %v: an entry with %d key bytes", tc.access, tc.keys, len(e.Key))
			}
		}
	}
}

// The log is asked again before each answer: a peer that loses access in the middle of a stream gets the answer of a
// missing log in the place of the next one.
func TestServeStreamStopsWhenAccessEnds(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	var calls atomic.Int64
	// HEAD_REQ, STREAM_REQ and the first answer ask; the second answer does not get through.
	a.srv = NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) Access {
		if calls.Add(1) <= 3 {
			return Keys
		}
		return NoAccess
	})
	l := sizedLog(t, a, repeat(600<<10, 6))
	a.srv.Offer(l)
	c := newStreamClient(t, a, b, l)
	c.send(message{typ: tStreamReq, size: c.size, keys: true, credit: maxCredit})
	c.answer(0)
	c.ended(codeNotFound)
}

// A withdrawn log is not served on, either.
func TestServeStreamStopsWhenTheLogIsWithdrawn(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	l := sizedLog(t, a, repeat(600<<10, 6))
	a.srv.Offer(l)
	c := newStreamClient(t, a, b, l)
	c.send(message{typ: tStreamReq, size: c.size, keys: true, credit: 100 << 10})
	c.answer(0)
	a.srv.Withdraw(l.Header().LogKey, l.ID())
	c.send(message{typ: tCreditReq, credit: maxCredit})
	c.ended(codeNotFound)
}

func TestFeed(t *testing.T) {
	var f feed
	if code := f.apply(message{typ: tCreditReq, credit: 5}, 10); code != codeProtocol {
		t.Fatalf("credit before a stream: %d", code)
	}
	if code := f.apply(message{typ: tStreamReq, a: 2, size: 10, credit: 7, keys: true}, 10); code != 0 {
		t.Fatalf("stream: %d", code)
	}
	if f != (feed{open: true, next: 2, size: 10, keys: true, credit: 7}) {
		t.Fatalf("feed %+v", f)
	}
	f.credit = -3
	if code := f.apply(message{typ: tCreditReq, credit: 5}, 10); code != 0 || f.credit != 2 {
		t.Fatalf("credit on a debt: %d, %d", code, f.credit)
	}
	if code := f.apply(message{typ: tCreditReq, credit: maxCredit}, 10); code != 0 || f.credit != maxCredit {
		t.Fatalf("credit is capped: %d, %d", code, f.credit)
	}
	// A request that is refused leaves the feed as it was.
	before := f
	if code := f.apply(message{typ: tStreamReq, a: 10, size: 10, credit: 1}, 10); code != codeProtocol || f != before {
		t.Fatalf("bad stream request: %d, %+v", code, f)
	}
	if code := f.apply(message{typ: tEntriesReq}, 10); code != codeProtocol {
		t.Fatalf("other type: %d", code)
	}
}
