package kolosync

import (
	"bytes"
	"errors"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// trickle writes b in pieces of piece bytes, one every gap.
func trickle(st *kolotransport.Stream, b []byte, piece int, gap time.Duration) {
	for len(b) > 0 {
		n := min(len(b), piece)
		if _, err := st.Write(b[:n]); err != nil {
			return
		}
		b = b[n:]
		time.Sleep(gap)
	}
}

// An answer that moves MinProgress bytes within every Timeout is read whatever its average speed: 4 KiB every 500 ms
// is 8 KiB/s, below 16 KiB/s, and 16 KiB arrive in 2 s, within the 3 s timeout of the tests.
func TestSlowButMovingAnswerIsRead(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	ba, ab := connect(t, b, a, nil)
	const size = 64 << 10
	rawServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		trickle(st, frame(size, make([]byte, size)), 4<<10, 500*time.Millisecond)
	})
	st := rawStream(t, ba)
	if _, err := st.Write(frame(1, []byte{0})); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := readMsg(st, false)
	if errors.Is(err, ErrTimeout) {
		t.Fatalf("readMsg after %v = %v: cut off while it moved", time.Since(start), err)
	}
}

// A peer that moves less than MinProgress bytes within a Timeout is cut off after that Timeout, whatever the size of the
// message it announced.
func TestTrickledAnswerIsCut(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	ba, ab := connect(t, b, a, nil)
	const size = 1 << 20
	stop := make(chan struct{})
	rawServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		body := frame(size, make([]byte, size))
		for i := 0; i < len(body); i += 1 << 10 {
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
			if _, err := st.Write(body[i : i+1<<10]); err != nil {
				return
			}
		}
	})
	defer close(stop)
	st := rawStream(t, ba)
	if _, err := st.Write(frame(1, []byte{0})); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := readMsg(st, false)
	if took := time.Since(start); !errors.Is(err, ErrTimeout) || took > 3*timeout {
		t.Fatalf("readMsg after %v = %v, want ErrTimeout within %v", took, err, 3*timeout)
	}
}

// A writer whose reader moves the message faster than writeMinRate is not cut off, though the message waits behind the
// reader's window longer than the timeout plus its size at 16 KiB/s.
func TestSlowReaderIsServed(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	small := &kolosecure.Config{Transport: &kolotransport.Config{MaxStreamReceiveWindow: 64 << 10, MaxConnReceiveWindow: 64 << 10}}
	ab, ba := connect(t, a, b, small) // b reads, with the small windows
	const size = 320 << 10
	wrote := make(chan error, 1)
	acceptServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		_, err := writeMsg(st, message{typ: tProof, proof: make([]byte, size)})
		wrote <- err
	})
	st := rawStream(t, ba)
	if _, err := writeMsg(st, headReq(a.id.PublicKey(), kololog.LogID{1})); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4<<10)
	st.SetReadDeadline(time.Now().Add(2 * time.Minute))
	var err error
	for err == nil {
		select {
		case err = <-wrote:
			if err != nil {
				t.Fatalf("writeMsg = %v: cut off while the reader took its bytes", err)
			}
			return
		case <-time.After(570 * time.Millisecond): // 7 KiB/s
		}
		_, err = st.Read(buf)
	}
	if err := <-wrote; err != nil {
		t.Fatalf("writeMsg = %v: cut off while the reader took its bytes", err)
	}
}

// A request is a few bytes: one announced larger than any request is refused before its body arrives.
func TestLargeRequestRefusedAtOnce(t *testing.T) {
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	ba, _ := connect(t, b, a, nil)
	st := rawStream(t, ba)
	st.Write(frame(maxSmall+1, nil))
	start := time.Now()
	got := readAll(t, st)
	if want := wire(message{typ: tError, code: codeTooLarge}); !bytes.Equal(got, want) || time.Since(start) > timeout {
		t.Fatalf("answer %x after %v, want %x at once", got, time.Since(start), want)
	}
}

// Received counts the bytes of the answer being read, so it moves before the answer is whole, while Bytes counts it
// once it is.
func TestMeterReceivedMovesWithinAnAnswer(t *testing.T) {
	checkGoroutines(t)
	half := make(chan struct{})
	_, _, l, r, bc, _ := streamScenario(t, []int{200 << 10}, func(st *kolotransport.Stream, kind byte, n int, real []byte) bool {
		if kind != 'E' || n != 0 {
			return false
		}
		st.Write(real[:len(real)/2])
		<-half
		st.Write(real[len(real)/2:])
		return true
	})
	var m PullMeter
	done := make(chan error, 1)
	go func() {
		_, err := PullWith(testCtx(t), bc, r, &PullOptions{Meter: &m})
		done <- err
	}()
	deadline := time.Now().Add(2 * timeout)
	var s PullStats
	for time.Now().Before(deadline) {
		if s = m.Stats(); s.Received >= 64<<10 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(half)
	if s.Received < 64<<10 || s.Bytes != 0 || s.Answers != 0 {
		t.Fatalf("half an answer in: Received %d, Bytes %d, Answers %d", s.Received, s.Bytes, s.Answers)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s = m.Stats(); s.Received != s.Bytes || s.Answers != 1 {
		t.Fatalf("after the pull: Received %d, Bytes %d, Answers %d", s.Received, s.Bytes, s.Answers)
	}
	sameEntries(t, r, l)
}

// A writer whose reader keeps reading but averages under writeMinRate over the whole message is cut off, so a slow reader
// cannot hold an answer's memory for hours.
func TestWriteCeiling(t *testing.T) {
	was := writeMinRate
	writeMinRate = 64 << 10 // the ceiling of 256 KiB is then 3 s + 4 s
	t.Cleanup(func() { writeMinRate = was })
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	small := &kolosecure.Config{Transport: &kolotransport.Config{MaxStreamReceiveWindow: 64 << 10, MaxConnReceiveWindow: 64 << 10}}
	ab, ba := connect(t, a, b, small)
	const size = 256 << 10
	wrote := make(chan error, 1)
	start := make(chan time.Time, 1)
	acceptServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		start <- time.Now()
		_, err := writeMsg(st, message{typ: tProof, proof: make([]byte, size)})
		wrote <- err
	})
	st := rawStream(t, ba)
	if _, err := writeMsg(st, headReq(a.id.PublicKey(), kololog.LogID{1})); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8<<10)
	st.SetReadDeadline(time.Now().Add(time.Minute))
	for {
		select {
		case err := <-wrote:
			took := time.Since(<-start)
			if !errors.Is(err, ErrTimeout) || took > 10*time.Second {
				t.Fatalf("writeMsg after %v = %v, want ErrTimeout at the ceiling of about 7 s", took, err)
			}
			return
		case <-time.After(500 * time.Millisecond): // 16 KiB/s, under 64 KiB/s
		}
		if _, err := st.Read(buf); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
}
