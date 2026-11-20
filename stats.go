package kolosync

import (
	"math"
	"sync"
	"time"
)

// PullStats says where the time of a pull went and how full it kept the link. All durations are wall time.
type PullStats struct {
	// Streamed is true when the peer served the entries as a stream (STREAM_REQ) and false when the pull asked for them one
	// answer at a time, as for a peer that does not stream.
	Streamed bool
	// Elapsed is the time since the pull started, or its whole length once it has ended.
	Elapsed time.Duration
	// Bytes, Entries and Answers count the ENTRIES answers read: their message bytes, entries and messages.
	Bytes   uint64
	Entries uint64
	Answers uint64
	// Requests counts the requests for entries sent: ENTRIES_REQ, or STREAM_REQ and CREDIT_REQ.
	Requests uint64
	// ReaderWait is the time the reader spent waiting for the bytes of answers, not counting waits for memory.
	ReaderWait time.Duration
	// CommitBusy is the time the goroutine that stores the answers spent verifying and storing them, and CommitIdle the
	// time it spent waiting for an answer.
	CommitBusy time.Duration
	CommitIdle time.Duration
	// FirstByteMin, FirstByteAvg and FirstByteMax are the time from writing the request for entries to reading the
	// first bytes of its answer. A request sent while others wait includes the time of the answers before it; a streamed
	// pull has one sample for each fill: its STREAM_REQ.
	FirstByteMin time.Duration
	FirstByteAvg time.Duration
	FirstByteMax time.Duration
	// InFlightMax and InFlightAvg are the most requests for entries asked for and not yet answered, and their average over
	// time. For a streamed pull a request is 2 MiB of credit.
	InFlightMax int
	InFlightAvg float64
	// InFlightBlocked counts the times the limit on requests in flight, PullOptions.InFlight, held a request back.
	InFlightBlocked uint64
	// MemoryBlocked counts the times the reader had to wait for room under the 6 MiB of answers a pull holds, and
	// MemoryWait is the time it waited. HeldMax is the most bytes of answers held at once.
	MemoryBlocked uint64
	MemoryWait    time.Duration
	HeldMax       int
}

// AvgAnswer returns the average size in bytes of an ENTRIES answer, 0 if none was read.
func (s PullStats) AvgAnswer() uint64 {
	if s.Answers == 0 {
		return 0
	}
	return s.Bytes / s.Answers
}

// PullMeter collects the statistics of a pull while it runs. Its zero value is ready to use: pass it in
// PullOptions.Meter and call Stats from any goroutine. A meter measures one pull at a time: starting a pull with a
// meter another pull is using is ErrInvalidArgument, and one that starts after the last has ended resets it.
type PullMeter struct {
	mu       sync.Mutex
	start    time.Time
	end      time.Time
	s        PullStats
	fbSum    time.Duration
	fbN      uint64
	inflight int
	since    time.Time // when inflight last changed
	area     float64   // sum of inflight times seconds
}

// Stats returns the statistics so far, or the whole pull's once it has ended; it is safe to call at any time.
func (m *PullMeter) Stats() PullStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.s
	if m.start.IsZero() {
		return s
	}
	now := m.end
	if now.IsZero() {
		now = time.Now()
	}
	s.Elapsed = now.Sub(m.start)
	if m.fbN > 0 {
		s.FirstByteAvg = m.fbSum / time.Duration(m.fbN)
	}
	area := m.area
	if m.end.IsZero() {
		area += float64(m.inflight) * now.Sub(m.since).Seconds()
	}
	if s.Elapsed > 0 {
		s.InFlightAvg = area / s.Elapsed.Seconds()
	}
	return s
}

// begin resets m for a pull that starts now; it reports false, and changes nothing, if a pull is still using m.
func (m *PullMeter) begin() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.start.IsZero() && m.end.IsZero() {
		return false
	}
	now := time.Now()
	m.start, m.end, m.since = now, time.Time{}, now
	m.s, m.fbSum, m.fbN, m.inflight, m.area = PullStats{}, 0, 0, 0, 0
	return true
}

// finish fixes the length of the pull.
func (m *PullMeter) finish() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.end.IsZero() {
		return
	}
	now := time.Now()
	m.area += float64(m.inflight) * now.Sub(m.since).Seconds()
	m.since = now
	m.end = now
}

func (m *PullMeter) streamed() {
	m.mu.Lock()
	m.s.Streamed = true
	m.mu.Unlock()
}

// requested counts a request for entries.
func (m *PullMeter) requested() {
	m.mu.Lock()
	m.s.Requests++
	m.mu.Unlock()
}

// inFlight records that n requests for entries are now waiting.
func (m *PullMeter) inFlight(n int) {
	m.mu.Lock()
	now := time.Now()
	m.area += float64(m.inflight) * now.Sub(m.since).Seconds()
	m.since, m.inflight = now, n
	m.s.InFlightMax = max(m.s.InFlightMax, n)
	m.mu.Unlock()
}

func (m *PullMeter) inFlightBlocked() {
	m.mu.Lock()
	m.s.InFlightBlocked++
	m.mu.Unlock()
}

// firstByte records the time of one request to the first bytes of its answer.
func (m *PullMeter) firstByte(d time.Duration) {
	m.mu.Lock()
	if m.fbN == 0 || d < m.s.FirstByteMin {
		m.s.FirstByteMin = d
	}
	m.s.FirstByteMax = max(m.s.FirstByteMax, d)
	m.fbSum += d
	m.fbN++
	m.mu.Unlock()
}

// readerWait adds time the reader waited for the bytes of answers.
func (m *PullMeter) readerWait(d time.Duration) {
	m.mu.Lock()
	m.s.ReaderWait += d
	m.mu.Unlock()
}

// memory records that held bytes of answers are held now, after a wait of waited, if more than 0, for room.
func (m *PullMeter) memory(held int, waited time.Duration) {
	m.mu.Lock()
	m.s.HeldMax = max(m.s.HeldMax, held)
	if waited > 0 {
		m.s.MemoryBlocked++
		m.s.MemoryWait += waited
	}
	m.mu.Unlock()
}

// answerRead counts an ENTRIES answer of n bytes with k entries.
func (m *PullMeter) answerRead(n int, k int) {
	m.mu.Lock()
	m.s.Answers++
	m.s.Bytes += uint64(n)
	m.s.Entries += uint64(k)
	m.mu.Unlock()
}

// committed adds the busy and idle time of the goroutine that stores answers.
func (m *PullMeter) committed(busy, idle time.Duration) {
	m.mu.Lock()
	m.s.CommitBusy += busy
	m.s.CommitIdle += idle
	m.mu.Unlock()
}

const (
	// requestCredit is the credit one request of a streamed pull grants, in bytes of ENTRIES answers: two answers of 1 MiB.
	requestCredit = 2 << 20
	// minWindow is the shortest time over which the speed of a streamed pull is measured.
	minWindow = 20 * time.Millisecond
)

// pace measures the round trip and the speed of a streamed pull and says how many requests it should keep in flight.
type pace struct {
	rtt    time.Duration // the shortest first-byte time seen
	rate   float64       // bytes a second, averaged over windows
	start  time.Time     // of the window in progress
	bytes  int
	maxReq int // the most requests in flight, PullOptions.InFlight or MaxInFlight
}

// sample notes a round trip of d.
func (p *pace) sample(d time.Duration) {
	if d > 0 && (p.rtt == 0 || d < p.rtt) {
		p.rtt = d
	}
}

// arrived notes n bytes read at now.
func (p *pace) arrived(now time.Time, n int) {
	if p.start.IsZero() {
		p.start = now
	}
	p.bytes += n
	win := max(p.rtt, minWindow)
	if el := now.Sub(p.start); el >= win {
		r := float64(p.bytes) / el.Seconds()
		if p.rate == 0 {
			p.rate = r
		} else {
			p.rate = (p.rate + r) / 2
		}
		p.start, p.bytes = now, 0
	}
}

// requests returns how many requests of requestCredit to keep in flight: twice the bandwidth-delay product measured,
// at least 2 so the peer always has a request waiting, and at most maxReq; 1 if maxReq is 1.
func (p *pace) requests() (n int, capped bool) {
	want := int(math.Ceil(2 * p.rate * p.rtt.Seconds() / requestCredit))
	n = max(want, min(2, p.maxReq))
	return min(n, p.maxReq), n > p.maxReq
}
