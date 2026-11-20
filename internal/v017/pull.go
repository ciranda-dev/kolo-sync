package v017

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// Pull brings rep up to date with the copy of its log that the peer on conn serves, then applies the peer's
// delete markers and, if the peer gives them, the keys rep lacks; a key other than one rep holds is ErrInvalid.
// Only rep's Update, ApplyDelete and AddKey store anything, and each verifies first. A second Pull of the same
// replica while one runs returns ErrBusy; pulls of different replicas may run at once on one connection.
// It asks for DefaultInFlight answers at a time; PullOptions.InFlight changes that.
func Pull(ctx context.Context, conn Conn, rep *kolostore.Replica) error {
	_, err := pull(ctx, conn, rep, true, PullOptions{})
	return err
}

// PullOptions changes how PullWith pulls; the zero value pulls as Pull does.
type PullOptions struct {
	// NoMarkers makes the pull neither request nor store delete markers: a chunk is stored only up
	// to its first deleted entry (ErrMarked), and STATE markers are ignored.
	NoMarkers bool
	// KeysFrom is the first index the caller may hold without its key; the pull scans and asks for
	// keys only from there.
	KeysFrom uint64
	// InFlight is how many answers of entries the pull asks for before the first is stored, so that the next ones travel
	// while one is verified and stored; 0 is DefaultInFlight, 1 asks for each after the one before is stored, and the
	// most is MaxInFlight. Answers that wait are stored in one commit, and the pull holds at most 6 MiB of answers not yet stored whatever it is.
	InFlight int
}

// PullResult is what PullWith reports.
type PullResult struct {
	// KeysFrom is the first index still held without its key after the pull.
	KeysFrom uint64
}

// PullWith is Pull with opts (nil for none). On an error the result's KeysFrom is opts.KeysFrom, and a
// KeysFrom past rep.Len() is ErrInvalidArgument.
func PullWith(ctx context.Context, conn Conn, rep *kolostore.Replica, opts *PullOptions) (PullResult, error) {
	var o PullOptions
	if opts != nil {
		o = *opts
	}
	from, err := pull(ctx, conn, rep, true, o)
	if err != nil {
		return PullResult{KeysFrom: o.KeysFrom}, err
	}
	for ; from < rep.Len(); from++ {
		info, err := rep.EntryInfo(from)
		if err != nil {
			return PullResult{KeysFrom: o.KeysFrom}, fmt.Errorf("kolosync: %w", err)
		}
		if !info.Deleted && !info.Keyed {
			break
		}
	}
	return PullResult{KeysFrom: from}, nil
}

// PullCiphertext is Pull for a peer that must never hold entry keys: it never asks for them, never calls
// AddKey, and an answer that carries a key anyway is ErrProtocol, with nothing from it stored.
func PullCiphertext(ctx context.Context, conn Conn, rep *kolostore.Replica) error {
	_, err := pull(ctx, conn, rep, false, PullOptions{})
	return err
}

// pull returns the index from which entries may still lack their key.
func pull(ctx context.Context, conn Conn, rep *kolostore.Replica, keys bool, o PullOptions) (uint64, error) {
	if noConn(conn) || rep == nil {
		return 0, ErrInvalidArgument
	}
	if o.InFlight < 0 || o.InFlight > MaxInFlight {
		return 0, fmt.Errorf("%w: InFlight %d is not 0 to %d", ErrInvalidArgument, o.InFlight, MaxInFlight)
	}
	if o.KeysFrom > rep.Len() {
		return 0, fmt.Errorf("%w: KeysFrom %d past the replica's %d entries", ErrInvalidArgument, o.KeysFrom, rep.Len())
	}
	if _, running := pulling.LoadOrStore(rep, struct{}{}); running {
		return 0, fmt.Errorf("%w: another Pull of this replica is running", ErrBusy)
	}
	defer pulling.Delete(rep)
	c, h, _, err := open(ctx, conn, rep.Header().LogKey, rep.ID())
	if err != nil {
		return 0, err
	}
	defer c.close()
	c.keys, c.noMarkers, c.from, c.depth = keys, o.NoMarkers, o.KeysFrom, cmp.Or(o.InFlight, DefaultInFlight)
	err = c.result(c.pull(rep, h))
	return c.from, err
}

// FetchHeader returns the signed header of the log logID that the peer on conn serves, checked against owner,
// for opening a new replica with kolostore.Store.OpenReplica.
func FetchHeader(ctx context.Context, conn Conn, owner ed25519.PublicKey, logID kololog.LogID) ([]byte, error) {
	if noConn(conn) || len(owner) != ed25519.PublicKeySize {
		return nil, ErrInvalidArgument
	}
	c, _, header, err := open(ctx, conn, owner, logID)
	if err != nil {
		return nil, err
	}
	c.close()
	lh, err := kololog.DecodeLogHeader(header)
	if err == nil {
		err = kololog.VerifyLogHeader(owner, lh)
	}
	if err == nil && lh.LogID != logID {
		err = kololog.ErrBadLogHeader
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return header, nil
}

// pulling holds the replicas a Pull is running on.
var pulling sync.Map

// client is the pulling end of one stream.
type client struct {
	ctx       context.Context
	st        *kolotransport.Stream
	stop      func() bool
	keys      bool   // ask for entry keys
	noMarkers bool   // PullOptions.NoMarkers
	from      uint64 // the first index that may lack its key
	depth     int    // PullOptions.InFlight
}

// open opens a stream for the log logID of owner and returns the peer's head, not yet verified, and its header.
func open(ctx context.Context, conn Conn, owner ed25519.PublicKey, logID kololog.LogID) (*client, kololog.Head, []byte, error) {
	// OpenStream waits while the peer gives no stream credit, so it gets the same bound as a message.
	octx, cancel := context.WithTimeout(ctx, timeout)
	st, err := conn.OpenStream(octx)
	cancel()
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return nil, kololog.Head{}, nil, ctx.Err()
	case octx.Err() != nil:
		return nil, kololog.Head{}, nil, fmt.Errorf("%w: opening a stream", ErrTimeout)
	default:
		return nil, kololog.Head{}, nil, ioErr(err)
	}
	c := &client{ctx: ctx, st: st}
	c.stop = context.AfterFunc(ctx, func() {
		_ = st.CancelRead(0)
		_ = st.CancelWrite(0)
	})
	req := message{typ: tHeadReq, logID: logID}
	copy(req.owner[:], owner)
	resp, err := c.call(req, tHead)
	if err != nil {
		c.close()
		return nil, kololog.Head{}, nil, c.result(err)
	}
	h, err := kololog.DecodeHead(resp.head)
	if err != nil {
		c.close()
		return nil, kololog.Head{}, nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return c, h, resp.header, nil
}

func (c *client) close() {
	c.stop()
	end(c.st)
}

// result returns ctx.Err() once ctx is done, since the stream errors are then only its echo.
func (c *client) result(err error) error {
	if err != nil && c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	return err
}

// call sends one request and reads its answer, which must have type want.
func (c *client) call(req message, want uint64) (message, error) {
	if _, err := writeMsg(c.st, req); err != nil {
		return message{}, err
	}
	m, err := readMsg(c.st, false)
	if err != nil {
		return message{}, err
	}
	return checkAnswer(m, want)
}

// checkAnswer returns m if it has type want, else the error that the peer's refusal or the unexpected message is.
func checkAnswer(m message, want uint64) (message, error) {
	if m.typ == tError {
		switch m.code {
		case codeNotFound:
			return message{}, ErrNotFound
		case codeBusy:
			return message{}, ErrBusy
		case codeTooLarge:
			return message{}, fmt.Errorf("%w: the peer could not send or accept a message", ErrTooLarge)
		}
		return message{}, fmt.Errorf("%w: the peer refused a request", ErrProtocol)
	}
	if m.typ != want {
		wipe(m)
		return message{}, fmt.Errorf("%w: unexpected message", ErrProtocol)
	}
	return m, nil
}

func (c *client) pull(rep *kolostore.Replica, h kololog.Head) error {
	owner := rep.Header().LogKey
	theirs, err := kololog.VerifyHead(owner, rep.ID(), h)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	m := theirs.Size()
	if m <= rep.Len() {
		// We hold the peer's range: the replica checks the head against its own tree.
		err := rep.Update(h, kololog.ConsistencyProof{}, nil)
		if err != nil && !errors.Is(err, kololog.ErrRollback) {
			return checked(err)
		}
		if t, _, ok := rep.Target(); ok && c.noMarkers {
			return behind(m, t.Size)
		}
	} else if err := c.fetch(rep, h, theirs); err != nil {
		return err
	}
	return c.state(rep, min(rep.Len(), m))
}

// fetch checks that the peer's head extends ours (get-sth-consistency), then gets the missing entries
// in chunks of one message (get-entries), each with the proof that it is a prefix of the peer's head.
func (c *client) fetch(rep *kolostore.Replica, h kololog.Head, theirs kololog.VerifiedHead) error {
	m := theirs.Size()
	if oh, err := rep.Head(); err == nil {
		ours, err := kololog.VerifyHead(theirs.LogKey(), theirs.LogID(), oh)
		if err != nil {
			return fmt.Errorf("kolosync: %w", err)
		}
		p, err := c.proof(ours.Size(), m)
		if err != nil {
			return err
		}
		if !kololog.VerifyConsistency(ours, theirs, p) {
			return c.diverged(rep, ours.Size(), kololog.ErrBadProof)
		}
	} else if !errors.Is(err, kololog.ErrNoHead) {
		return fmt.Errorf("kolosync: %w", err)
	}
	// An interrupted catch-up left a target: fill it first, since the replica only grows toward it.
	if t, _, ok := rep.Target(); ok && t.Size != m {
		if m < t.Size {
			// The peer is behind the head we are filling, unless its record at our last index proves a fork.
			if c.forked(rep, rep.Len()) {
				return ErrDiverged
			}
			if c.noMarkers {
				return behind(m, t.Size)
			}
			return nil
		}
		if err := c.fill(rep, t, t.Size); err != nil {
			return err
		}
	}
	return c.fill(rep, h, m)
}

// behind is PullWith's answer, with NoMarkers, to a peer that cannot bring the replica to the head it is filling.
func behind(m, target uint64) error {
	return fmt.Errorf("%w: the peer holds %d entries, the replica fills toward %d", ErrBehind, m, target)
}

func markedAt(i uint64) error {
	return fmt.Errorf("%w: entry %d", ErrMarked, i)
}

// diverged returns ErrDiverged if forked proves two histories, else ErrInvalid wrapping cause: the peer's proof was bad.
func (c *client) diverged(rep *kolostore.Replica, n uint64, cause error) error {
	if c.forked(rep, n) {
		return ErrDiverged
	}
	return fmt.Errorf("%w: %w", ErrInvalid, cause)
}

// forked reports whether the peer's record at index n-1 is signed by the owner but differs from ours.
func (c *client) forked(rep *kolostore.Replica, n uint64) bool {
	if n == 0 {
		return false
	}
	resp, err := c.call(message{typ: tEntriesReq, a: n - 1, b: n - 1}, tEntries)
	if err != nil {
		return false
	}
	defer wipe(resp)
	mine, err := rep.Record(n - 1)
	if err != nil || len(resp.entries) != 1 {
		return false
	}
	theirs, err := kololog.DecodeRecord(resp.entries[0].Record)
	return err == nil && theirs.Index == n-1 && kololog.VerifyRecord(mine.LogKey, mine.LogID, theirs) && !bytes.Equal(theirs.Encode(), mine.Encode())
}

func (c *client) proof(first, second uint64) (kololog.ConsistencyProof, error) {
	resp, err := c.call(message{typ: tProofReq, a: first, b: second}, tProof)
	if err != nil {
		return kololog.ConsistencyProof{}, err
	}
	p, err := kololog.DecodeConsistencyProof(resp.proof)
	if err != nil {
		return kololog.ConsistencyProof{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return p, nil
}

// state applies the peer's delete markers for the first n entries, unless noMarkers, and its keys from the
// first entry from c.from we hold without one, so a pull does not fetch keys we have.
func (c *client) state(rep *kolostore.Replica, n uint64) error {
	if !c.keys {
		return c.stateRange(rep, 0, n, false)
	}
	f := n
	for i := min(c.from, n); i < n; i++ {
		info, err := rep.EntryInfo(i)
		if err != nil {
			return fmt.Errorf("kolosync: %w", err)
		}
		if !info.Deleted && !info.Keyed {
			f = i
			break
		}
	}
	c.from = max(c.from, f)
	if !c.noMarkers {
		if err := c.stateRange(rep, 0, f, false); err != nil {
			return err
		}
	}
	return c.stateRange(rep, f, n, true)
}

func (c *client) stateRange(rep *kolostore.Replica, start, n uint64, keys bool) error {
	for start < n {
		resp, err := c.call(message{typ: tStateReq, a: start, b: n - 1, keys: keys}, tState)
		if err != nil {
			return err
		}
		err = unasked(resp, keys)
		if err == nil {
			err = c.apply(rep, resp, start, n)
		}
		wipe(resp)
		if err != nil {
			return err
		}
		start = resp.a
	}
	return nil
}

// unasked returns ErrProtocol if an answer to a request that did not ask for keys carries one.
func unasked(m message, keys bool) error {
	if keys {
		return nil
	}
	for _, e := range m.entries {
		if len(e.Key) != 0 {
			return fmt.Errorf("%w: a key the request did not ask for", ErrProtocol)
		}
	}
	for _, it := range m.items {
		if it.key != nil {
			return fmt.Errorf("%w: a key the request did not ask for", ErrProtocol)
		}
	}
	return nil
}

// apply checks every item of a STATE answer, then applies its markers in one ApplyDelete, all or none, and then its keys.
func (c *client) apply(rep *kolostore.Replica, m message, start, n uint64) error {
	if m.a <= start || m.a > n {
		return fmt.Errorf("%w: state ends at %d", ErrProtocol, m.a)
	}
	var markers [][]byte
	var keys []item
	for _, it := range m.items {
		if it.index < start || it.index >= m.a {
			return fmt.Errorf("%w: state item out of range", ErrProtocol)
		}
		if it.marker != nil {
			if c.noMarkers {
				continue
			}
			dm, err := kololog.DecodeDeleteMarker(it.marker)
			if err != nil {
				return checked(err)
			}
			if dm.Index != it.index {
				return fmt.Errorf("%w: marker for entry %d listed at %d", ErrProtocol, dm.Index, it.index)
			}
		}
		info, err := rep.EntryInfo(it.index)
		if err != nil {
			return fmt.Errorf("kolosync: %w", err)
		}
		// A key for an entry we hold deleted is dropped: the peer has not seen the delete yet.
		switch {
		case info.Deleted:
		case it.marker != nil:
			markers = append(markers, it.marker)
		default:
			keys = append(keys, it)
		}
	}
	if err := checked(rep.ApplyDelete(markers...)); err != nil {
		return err
	}
	for _, it := range keys {
		if err := checked(rep.AddKey(it.index, it.key)); err != nil {
			return err
		}
	}
	return nil
}

// checked maps the replica's verification errors to ErrInvalid and wraps the rest.
func checked(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, kololog.ErrDiverged):
		return fmt.Errorf("%w: %w", ErrDiverged, err)
	case errors.Is(err, kololog.ErrBadEntry), errors.Is(err, kololog.ErrBadProof),
		errors.Is(err, kololog.ErrInvalidHead), errors.Is(err, kololog.ErrMalformed):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return fmt.Errorf("kolosync: %w", err)
}
