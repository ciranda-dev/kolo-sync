package kolosync

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"sync"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-sync/internal/backoff"
)

const (
	defaultMaxPulls        = 32
	defaultMaxPullsPerConn = MaxStreams - 1 // the peer's server keeps one of its MaxStreams for the watch stream
	defaultRetryMin        = time.Second
	defaultRetryMax        = 10 * time.Minute
)

// FollowOptions are a Follower's bounds; a zero field takes its default.
type FollowOptions struct {
	Ciphertext      bool          // pull without entry keys, as PullCiphertext
	MaxPulls        int           // most pulls at once over all connections, default 32
	MaxPullsPerConn int           // most pulls at once on one connection, 1 to MaxStreams-1, default MaxStreams-1
	RetryMin        time.Duration // backoff floor after a failed pull of a log from a peer, at least 100 ms, default 1 s
	RetryMax        time.Duration // backoff ceiling, at least RetryMin, default 10 minutes
	Poll            time.Duration // how often a peer without WATCH is asked for heads, at least RetryMin; 0 never
}

// Follower keeps the replicas added to it up to date from every connection given to Follow. It is safe for concurrent use.
type Follower struct {
	opts   FollowOptions
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	clk clock
	rnd func(int64) int64
	// pull is PullWith or PullCiphertext, which tests replace.
	pull func(ctx context.Context, conn Conn, rep *kolostore.Replica, keysFrom uint64) (uint64, error)

	mu       sync.Mutex // guards what follows and the fields of followed, link and offer
	closed   bool
	logs     map[logName]*followed
	links    []*peerLink
	pulls    int
	retry    time.Time // when the timer for the earliest backoff fires, zero if none
	stop     func() bool
	events   map[evKey]FollowEvent
	order    []evKey
	eventsIn chan struct{}
}

type clock struct {
	now   func() time.Time
	after func(d time.Duration, fn func()) (stop func() bool)
}

var realClock = clock{
	now:   time.Now,
	after: func(d time.Duration, fn func()) func() bool { return time.AfterFunc(d, fn).Stop },
}

type evKey struct {
	name logName
	kind FollowEventKind
}

type followed struct {
	name      logName
	rep       *kolostore.Replica
	keysFrom  uint64
	lastGrown time.Time
	diverged  bool
	hint      uint64 // the largest verified head learned elsewhere
	hold      time.Time
	offers    map[*peerLink]*offer
	running   bool
	cancel    context.CancelFunc
	done      chan struct{}
}

type offer struct {
	size     uint64 // the largest verified head it offered
	head     kololog.VerifiedHead
	heard    bool
	hinted   uint64 // the hint a pull from it already tried
	fails    int
	retryAt  time.Time
	blocked  bool // it sent data that does not verify, or broke the protocol
	notFound bool // it does not serve the log
	owed     bool // its last pull failed, so one more is due even if its head is no larger than the replica
}

type peerLink struct {
	f       *Follower
	conn    Conn
	key     ed25519.PublicKey
	ctx     context.Context
	wg      sync.WaitGroup
	wake    chan struct{}
	added   []*followed // logs added since the watch stream, or the poll, last took the list
	running int
	ended   bool
}

var (
	// ErrClosed means the Follower is closed.
	ErrClosed = errors.New("kolosync: closed")
)

// NewFollower returns a Follower with opts, nil for the defaults.
func NewFollower(opts *FollowOptions) (*Follower, error) {
	var o FollowOptions
	if opts != nil {
		o = *opts
	}
	o.MaxPulls = cmp.Or(o.MaxPulls, defaultMaxPulls)
	o.MaxPullsPerConn = cmp.Or(o.MaxPullsPerConn, defaultMaxPullsPerConn)
	o.RetryMin = cmp.Or(o.RetryMin, defaultRetryMin)
	o.RetryMax = cmp.Or(o.RetryMax, defaultRetryMax)
	if o.MaxPulls < 1 || o.MaxPullsPerConn < 1 || o.MaxPullsPerConn > MaxStreams-1 ||
		o.RetryMin < 100*time.Millisecond || o.RetryMax < o.RetryMin ||
		(o.Poll != 0 && o.Poll < o.RetryMin) {
		return nil, ErrInvalidArgument
	}
	f := &Follower{
		opts:     o,
		clk:      realClock,
		logs:     make(map[logName]*followed),
		events:   make(map[evKey]FollowEvent),
		eventsIn: make(chan struct{}, 1),
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.rnd = rand.Int64N
	f.pull = f.pullWith
	return f, nil
}

func (f *Follower) pullWith(ctx context.Context, conn Conn, rep *kolostore.Replica, keysFrom uint64) (uint64, error) {
	if f.opts.Ciphertext {
		return keysFrom, PullCiphertext(ctx, conn, rep)
	}
	r, err := PullWith(ctx, conn, rep, &PullOptions{KeysFrom: keysFrom})
	return r.KeysFrom, err
}

// Add follows rep, whose header names the owner. A log already followed is ErrInvalidArgument.
func (f *Follower) Add(rep *kolostore.Replica) error {
	if rep == nil {
		return ErrInvalidArgument
	}
	n, ok := nameOf(rep.Header().LogKey, rep.ID())
	if !ok {
		return ErrInvalidArgument
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.closed:
		return ErrClosed
	case f.logs[n] != nil:
		return fmt.Errorf("%w: the log is already followed", ErrInvalidArgument)
	}
	fl := &followed{name: n, rep: rep, offers: make(map[*peerLink]*offer)}
	f.logs[n] = fl
	for _, l := range f.links {
		l.added = append(l.added, fl)
		select {
		case l.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// Remove stops following a log and returns once a pull of it has ended; the caller still owns and closes the replica.
func (f *Follower) Remove(owner ed25519.PublicKey, logID kololog.LogID) {
	n, ok := nameOf(owner, logID)
	if !ok {
		return
	}
	f.mu.Lock()
	fl := f.logs[n]
	if fl == nil {
		f.mu.Unlock()
		return
	}
	delete(f.logs, n)
	f.dropEvents(n)
	cancel, done := fl.cancel, fl.done
	f.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Follow watches and pulls the followed logs the peer on conn serves until ctx or conn ends, and returns why.
// It names every followed log to the peer (owner key, log ID, length), with no filter, so follow only a peer that may
// know them all, and it only opens streams; the caller runs Server.Serve on conn. A second Follow of the same conn is ErrBusy.
func (f *Follower) Follow(ctx context.Context, conn Conn) error {
	if noConn(conn) || len(conn.RemotePublicKey()) != ed25519.PublicKeySize {
		return ErrInvalidArgument
	}
	l := &peerLink{f: f, conn: conn, key: conn.RemotePublicKey(), wake: make(chan struct{}, 1)}
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return ErrClosed
	}
	for _, o := range f.links {
		if sameConn(o.conn, conn) {
			f.mu.Unlock()
			return ErrBusy
		}
	}
	l.ctx = lctx
	f.links = append(f.links, l)
	f.wg.Add(1)
	f.dispatch()
	f.mu.Unlock()
	defer f.wg.Done()
	defer context.AfterFunc(f.ctx, cancel)()
	err := l.run(lctx)
	cancel()
	f.mu.Lock()
	l.ended = true
	f.links = removeLink(f.links, l)
	f.mu.Unlock()
	l.wg.Wait()
	f.mu.Lock()
	for _, fl := range f.logs {
		delete(fl.offers, l)
	}
	f.dispatch()
	f.mu.Unlock()
	switch {
	case f.ctx.Err() != nil:
		return ErrClosed
	case ctx.Err() != nil:
		return ctx.Err()
	}
	return err
}

// sameConn reports whether a and b are the same connection; a Conn that is not a pointer is never taken for another.
func sameConn(a, b Conn) bool {
	return reflect.ValueOf(a).Kind() == reflect.Pointer && reflect.ValueOf(b).Kind() == reflect.Pointer && a == b
}

func removeLink(ls []*peerLink, l *peerLink) []*peerLink {
	for i, x := range ls {
		if x == l {
			return append(ls[:i], ls[i+1:]...)
		}
	}
	return ls
}

// Hint takes a head learned elsewhere; once verified, the log is pulled from a connected peer that may serve it.
func (f *Follower) Hint(h kololog.Head) error {
	n, ok := nameOf(h.LogKey, h.LogID)
	f.mu.Lock()
	closed, fl := f.closed, f.logs[n]
	f.mu.Unlock()
	switch {
	case closed:
		return ErrClosed
	case !ok:
		return ErrInvalid
	case fl == nil:
		return ErrNotFound
	}
	v, err := kololog.VerifyHead(fl.rep.Header().LogKey, fl.rep.ID(), h)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if v.Size() <= fl.rep.Len() {
		return f.checkLocal(fl, nil, v)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logs[n] != fl {
		return ErrNotFound
	}
	fl.hint = max(fl.hint, v.Size())
	for _, o := range fl.offers {
		o.notFound = false
	}
	f.dispatch()
	return nil
}

// checkLocal checks a verified head no larger than the replica against it, as Pull does, and reports a second history.
func (f *Follower) checkLocal(fl *followed, l *peerLink, v kololog.VerifiedHead) error {
	err := checked(fl.rep.Update(v.Head(), kololog.ConsistencyProof{}, nil))
	if !errors.Is(err, ErrDiverged) {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logs[fl.name] == fl {
		f.diverge(fl, l, err)
	}
	return err
}

func (f *Follower) diverge(fl *followed, l *peerLink, err error) {
	fl.diverged = true
	ev := FollowEvent{Kind: Diverged, Len: fl.rep.Len(), Err: err}
	if l != nil {
		ev.Peer = l.key
	}
	f.post(fl, ev)
}

// FollowStatus is what a Follower knows of one log.
type FollowStatus struct {
	Len       uint64    // the replica's length
	Largest   uint64    // the largest verified head size a connected peer offered
	Peers     int       // connected peers that offered a verified head of this log
	LastGrown time.Time // when a pull last made the replica longer; zero if never since Add
}

// Status returns what the follower knows of a log, or ErrNotFound if it does not follow it.
func (f *Follower) Status(owner ed25519.PublicKey, logID kololog.LogID) (FollowStatus, error) {
	n, ok := nameOf(owner, logID)
	f.mu.Lock()
	defer f.mu.Unlock()
	fl := f.logs[n]
	if !ok || fl == nil {
		return FollowStatus{}, ErrNotFound
	}
	s := FollowStatus{Len: fl.rep.Len(), LastGrown: fl.lastGrown}
	for _, o := range fl.offers {
		if o.heard {
			s.Peers++
			s.Largest = max(s.Largest, o.size)
		}
	}
	return s, nil
}

// FollowEventKind says what happened in a FollowEvent.
type FollowEventKind int

const (
	Grew       FollowEventKind = iota + 1 // a pull made the replica longer
	PullFailed                            // a pull from Peer failed with Err; the next try waits for the backoff
	Diverged                              // a peer served a second history (Err matches ErrDiverged); the log is no longer pulled
)

// FollowEvent is something that happened to a followed log.
type FollowEvent struct {
	Kind  FollowEventKind
	Owner ed25519.PublicKey
	LogID kololog.LogID
	Peer  ed25519.PublicKey
	Len   uint64
	Err   error
}

func (f *Follower) post(fl *followed, ev FollowEvent) {
	ev.Owner, ev.LogID, ev.Peer = slices.Clone(fl.name.owner[:]), fl.name.id, slices.Clone(ev.Peer)
	k := evKey{fl.name, ev.Kind}
	if _, waiting := f.events[k]; !waiting {
		f.order = append(f.order, k)
	}
	f.events[k] = ev
	select {
	case f.eventsIn <- struct{}{}:
	default:
	}
}

func (f *Follower) dropEvents(n logName) {
	f.order = slices.DeleteFunc(f.order, func(k evKey) bool { return k.name == n })
	for _, kind := range []FollowEventKind{Grew, PullFailed, Diverged} {
		delete(f.events, evKey{n, kind})
	}
}

// Next returns the next event; only the newest event per log and kind waits.
func (f *Follower) Next(ctx context.Context) (FollowEvent, error) {
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return FollowEvent{}, ErrClosed
		}
		if len(f.order) > 0 {
			k := f.order[0]
			f.order = f.order[1:]
			ev := f.events[k]
			delete(f.events, k)
			more := len(f.order) > 0
			f.mu.Unlock()
			if more {
				select {
				case f.eventsIn <- struct{}{}:
				default:
				}
			}
			return ev, nil
		}
		f.mu.Unlock()
		select {
		case <-f.eventsIn:
		case <-ctx.Done():
			return FollowEvent{}, ctx.Err()
		case <-f.ctx.Done():
			return FollowEvent{}, ErrClosed
		}
	}
}

// Close ends every Follow and pull and waits for them. Next, Add and Follow then return ErrClosed.
func (f *Follower) Close() error {
	f.mu.Lock()
	if f.stop != nil {
		f.stop()
	}
	f.closed = true
	f.mu.Unlock()
	f.cancel()
	f.wg.Wait()
	return nil
}

// dispatch starts the pulls that can start, and arms the timer for the earliest backoff that holds one back. f.mu is held.
func (f *Follower) dispatch() {
	if f.closed {
		return
	}
	now := f.clk.now()
	var next time.Time
	for _, fl := range f.logs {
		if f.pulls >= f.opts.MaxPulls {
			break
		}
		if fl.running || fl.diverged {
			continue
		}
		l, wake := f.source(fl, now)
		if l != nil {
			f.start(fl, l)
		} else if !wake.IsZero() && (next.IsZero() || wake.Before(next)) {
			next = wake
		}
	}
	if next.IsZero() || (!f.retry.IsZero() && !next.Before(f.retry)) {
		return
	}
	if f.stop != nil {
		f.stop()
	}
	f.retry = next
	f.stop = f.clk.after(next.Sub(now), func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.retry = time.Time{}
		f.dispatch()
	})
}

// source chooses the connection to pull fl from: of the peers not in backoff, the one with the largest head larger than
// the replica, and on a tie the one with fewer pulls running. If only backoff holds the log back it returns when that ends.
func (f *Follower) source(fl *followed, now time.Time) (best *peerLink, wake time.Time) {
	have := fl.rep.Len()
	if now.Before(fl.hold) {
		return nil, fl.hold
	}
	var size uint64
	for _, l := range f.links {
		o := fl.offers[l]
		if o == nil {
			o = new(offer)
		}
		eff := o.size
		if fl.hint > o.hinted {
			eff = max(eff, fl.hint)
		}
		if (eff <= have && !o.owed) || o.blocked || o.notFound || l.running >= f.opts.MaxPullsPerConn {
			continue
		}
		if now.Before(o.retryAt) {
			if wake.IsZero() || o.retryAt.Before(wake) {
				wake = o.retryAt
			}
			continue
		}
		if best == nil || eff > size || (eff == size && l.running < best.running) {
			best, size = l, eff
		}
	}
	return best, wake
}

// start begins a pull of fl from l. f.mu is held.
func (f *Follower) start(fl *followed, l *peerLink) {
	o := fl.offer(l)
	o.hinted = max(o.hinted, fl.hint)
	ctx, cancel := context.WithCancel(l.ctx)
	fl.running, fl.cancel, fl.done = true, cancel, make(chan struct{})
	l.running++
	f.pulls++
	l.wg.Add(1)
	go func(before, offered, keysFrom uint64) {
		defer l.wg.Done()
		keys, err := f.pull(ctx, l.conn, fl.rep, keysFrom)
		stale := f.pulled(ctx, fl, l, before, offered, keys, err)
		cancel()
		for _, s := range stale {
			_ = f.checkLocal(fl, s.l, s.head)
		}
	}(fl.rep.Len(), o.size, fl.keysFrom)
}

func (fl *followed) offer(l *peerLink) *offer {
	o := fl.offers[l]
	if o == nil {
		o = new(offer)
		fl.offers[l] = o
	}
	return o
}

// offeredHead is a head a peer offered that was larger than the replica when it arrived.
type offeredHead struct {
	l    *peerLink
	head kololog.VerifiedHead
}

// pulled records the end of a pull that began when the replica held before entries and the peer's head offered.
// It returns the heads offered during the pull that the replica now holds, which the caller checks against it.
func (f *Follower) pulled(ctx context.Context, fl *followed, l *peerLink, before, offered, keys uint64, err error) (stale []offeredHead) {
	f.mu.Lock()
	defer f.mu.Unlock()
	defer f.dispatch()
	fl.running, fl.cancel = false, nil
	l.running--
	f.pulls--
	close(fl.done)
	if f.logs[fl.name] != fl {
		return nil
	}
	now := f.clk.now()
	have := fl.rep.Len()
	fl.keysFrom = max(fl.keysFrom, keys)
	if have > before {
		fl.lastGrown = now
		f.post(fl, FollowEvent{Kind: Grew, Peer: l.key, Len: have})
		if !fl.diverged {
			for p, o := range fl.offers {
				if o.heard && o.size > before && o.size <= have && (p != l || o.size != offered) {
					stale = append(stale, offeredHead{p, o.head})
				}
			}
		}
	}
	o := fl.offer(l)
	fail := func() {
		o.fails, o.owed = o.fails+1, true
		o.retryAt = now.Add(backoff.Delay(o.fails, f.opts.RetryMin, f.opts.RetryMax, f.rnd))
		f.post(fl, FollowEvent{Kind: PullFailed, Peer: l.key, Len: have, Err: err})
	}
	switch {
	case ctx.Err() != nil:
	case err == nil:
		o.fails, o.owed = 0, false
		if have < offered {
			err = fmt.Errorf("%w: the peer holds fewer entries than its head", ErrBehind)
			fail()
		}
	case errors.Is(err, ErrDiverged):
		f.diverge(fl, l, err)
	case errors.Is(err, ErrNotFound):
		o.notFound = true
		f.post(fl, FollowEvent{Kind: PullFailed, Peer: l.key, Len: have, Err: err})
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrProtocol), errors.Is(err, ErrTooLarge):
		o.blocked = true
		f.post(fl, FollowEvent{Kind: PullFailed, Peer: l.key, Len: have, Err: err})
	case errors.Is(err, kolostore.ErrClosed), errors.Is(err, kolostore.ErrCorrupt), f.pullRunning(fl, err):
		fl.hold = now.Add(f.opts.RetryMin)
		f.post(fl, FollowEvent{Kind: PullFailed, Peer: l.key, Len: have, Err: err})
	default:
		fail()
	}
	return stale
}

// pullRunning reports whether err is the ErrBusy of another Pull of the replica, which is not the peer's doing.
func (f *Follower) pullRunning(fl *followed, err error) bool {
	if !errors.Is(err, ErrBusy) {
		return false
	}
	_, running := pulling.Load(fl.rep)
	return running
}

func (l *peerLink) takeAdded() []*followed {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	var out []*followed
	for _, fl := range l.added {
		if l.f.logs[fl.name] == fl {
			out = append(out, fl)
		}
	}
	l.added = nil
	return out
}

// all returns every followed log and forgets the logs added so far, which it includes.
func (l *peerLink) all() []*followed {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	out := make([]*followed, 0, len(l.f.logs))
	for _, fl := range l.f.logs {
		out = append(out, fl)
	}
	l.added = nil
	return out
}

func (f *Follower) sleep(ctx context.Context, d time.Duration) {
	done := make(chan struct{})
	stop := f.clk.after(d, func() { close(done) })
	select {
	case <-done:
	case <-ctx.Done():
		stop()
	}
}

// refused reports whether err is the peer's refusal or failure to answer, as opposed to the end of the connection.
func refused(err error) bool {
	for _, e := range []error{ErrBusy, ErrTimeout, ErrProtocol, ErrInvalid, ErrTooLarge, ErrNotFound} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// errNoWatch means the peer answered WATCH_REQ as a server of v0.1.0 does.
var errNoWatch = errors.New("kolosync: peer does not watch")

func (l *peerLink) run(ctx context.Context) error {
	var tooLarge, fails int
	for {
		fls := l.all()
		for len(fls) == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-l.wake:
				fls = l.all()
			}
		}
		err := l.watch(ctx, fls, &fails)
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case errors.Is(err, errNoWatch):
			return l.poll(ctx)
		case errors.Is(err, ErrTooLarge):
			if tooLarge++; tooLarge > 1 {
				return l.poll(ctx)
			}
		case refused(err):
			fails++
			l.f.sleep(ctx, backoff.Delay(fails, l.f.opts.RetryMin, l.f.opts.RetryMax, l.f.rnd))
		default:
			return err
		}
	}
}

type names struct {
	mu sync.Mutex
	m  map[logName]struct{}
}

// watch runs one watch stream that starts by naming fls, and returns why it ended; fails is reset when the peer answers.
func (l *peerLink) watch(ctx context.Context, fls []*followed, fails *int) error {
	octx, cancel := context.WithTimeout(ctx, timeout)
	st, err := l.conn.OpenStream(octx)
	cancel()
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return ctx.Err()
	case octx.Err() != nil:
		return fmt.Errorf("%w: opening a stream", ErrTimeout)
	default:
		return ioErr(err)
	}
	defer end(st)
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(sctx, func() {
		_ = st.CancelRead(0)
		_ = st.CancelWrite(0)
	})()
	nm := &names{m: make(map[logName]struct{})}
	if err := l.name(st, nm, fls); err != nil {
		return err
	}
	var werr error
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	wg.Go(func() {
		for {
			select {
			case <-sctx.Done():
				return
			case <-l.wake:
				if werr = l.name(st, nm, l.takeAdded()); werr != nil {
					cancel()
					return
				}
			}
		}
	})
	for first := true; ; first = false {
		var m message
		if first {
			m, err = readMsg(st, false)
		} else {
			m, err = readWatchMsg(st, false)
		}
		if err == nil && first && m.typ == tError && m.code == codeProtocol {
			return errNoWatch
		}
		if err == nil {
			m, err = checkAnswer(m, tWatch)
		}
		if err != nil {
			cancel()
			wg.Wait()
			return cmp.Or(werr, err)
		}
		*fails = 0
		for _, b := range m.heads {
			if err := l.head(nm, b); err != nil {
				return err
			}
		}
	}
}

func (l *peerLink) name(st *kolotransport.Stream, nm *names, fls []*followed) error {
	for len(fls) > 0 {
		k := min(len(fls), maxWatchItems)
		items := make([]watchItem, k)
		nm.mu.Lock()
		for i, fl := range fls[:k] {
			items[i] = watchItem{owner: fl.name.owner, logID: fl.name.id, held: fl.rep.Len()}
			nm.m[fl.name] = struct{}{}
		}
		nm.mu.Unlock()
		if _, err := writeMsg(st, message{typ: tWatchReq, watch: items}); err != nil {
			return err
		}
		fls = fls[k:]
	}
	return nil
}

func (l *peerLink) head(nm *names, b []byte) error {
	h, err := kololog.DecodeHead(b)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	n, ok := nameOf(h.LogKey, h.LogID)
	nm.mu.Lock()
	_, asked := nm.m[n]
	nm.mu.Unlock()
	if !ok || !asked {
		return fmt.Errorf("%w: a head of a log not asked for", ErrProtocol)
	}
	l.f.mu.Lock()
	fl := l.f.logs[n]
	l.f.mu.Unlock()
	if fl == nil {
		return nil
	}
	v, err := kololog.VerifyHead(fl.rep.Header().LogKey, fl.rep.ID(), h)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	l.f.offered(l, fl, v)
	return nil
}

// offered records a verified head of fl that the peer of l offered, and pulls if it is larger than the replica;
// if not, the replica checks it for a second history.
func (f *Follower) offered(l *peerLink, fl *followed, v kololog.VerifiedHead) {
	f.mu.Lock()
	if l.ended || f.logs[fl.name] != fl {
		f.mu.Unlock()
		return
	}
	o := fl.offer(l)
	o.heard, o.notFound = true, false
	if v.Size() >= o.size {
		o.size, o.head = v.Size(), v
	}
	if v.Size() > fl.rep.Len() {
		f.dispatch()
		f.mu.Unlock()
		return
	}
	diverged := fl.diverged
	f.mu.Unlock()
	if !diverged {
		_ = f.checkLocal(fl, l, v)
	}
}

func (l *peerLink) poll(ctx context.Context) error {
	tick := make(chan struct{}, 1)
	var stop func() bool
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	arm := func() {
		if l.f.opts.Poll > 0 {
			stop = l.f.clk.after(l.f.opts.Poll, func() {
				select {
				case tick <- struct{}{}:
				default:
				}
			})
		}
	}
	arm()
	fls := l.all()
	for {
		if err := l.fetchHeads(ctx, fls); err != nil {
			return err
		}
		for fls = nil; fls == nil; {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-l.wake:
				fls = l.takeAdded()
			case <-tick:
				fls = l.all()
				arm()
			}
		}
	}
}

func (l *peerLink) fetchHeads(ctx context.Context, fls []*followed) error {
	for _, fl := range fls {
		v, err := FetchHead(ctx, l.conn, fl.rep.Header().LogKey, fl.rep.ID())
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err == nil:
			l.f.offered(l, fl, v)
		case !refused(err):
			return err
		}
	}
	return nil
}
