package kolosync

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	kololog "github.com/ciranda-dev/kolo-log"
)

// Fetched is one entry that Fetch got from the peer and verified.
type Fetched struct {
	Index uint64
	Data  []byte // the entry's value, as kololog.Log.Get returns it; nil when Err is set
	// Err is kololog.ErrDeleted, kololog.ErrKeyUnavailable, ErrKeyMismatch or nil (see the README).
	Err error
}

// FetchHead returns the signed head of the log logID that the peer on conn serves, verified against owner.
func FetchHead(ctx context.Context, conn Conn, owner ed25519.PublicKey, logID kololog.LogID) (kololog.VerifiedHead, error) {
	if noConn(conn) || len(owner) != ed25519.PublicKeySize {
		return kololog.VerifiedHead{}, ErrInvalidArgument
	}
	c, h, _, err := open(ctx, conn, owner, logID)
	if err != nil {
		return kololog.VerifiedHead{}, err
	}
	c.close()
	v, err := kololog.VerifyHead(owner, logID, h)
	if err != nil {
		return kololog.VerifiedHead{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return v, nil
}

// Fetch gets the entries start to end, end included, of the log of h from the peer on conn, without a replica.
// Each entry is checked with its inclusion proof in the tree of h's size, so the peer must hold h's entries:
// a peer with a smaller head is ErrBehind, one with another root at h's size ErrDiverged.
func Fetch(ctx context.Context, conn Conn, h kololog.VerifiedHead, start, end uint64) ([]Fetched, error) {
	return FetchWithKeys(ctx, conn, h, start, end, nil)
}

// FetchWithKeys is Fetch for a caller that holds entry keys, such as one reading from a peer that serves
// ciphertext only; keys returns a copy of the key held for an entry that came without one (see the README).
// keys is asked after the stream is closed, so its use shows only in how long FetchWithKeys takes to return.
func FetchWithKeys(ctx context.Context, conn Conn, h kololog.VerifiedHead, start, end uint64,
	keys func(index uint64) (kololog.EntryKey, error)) ([]Fetched, error) {
	c, ph, err := openRange(ctx, conn, h, start, end)
	if err != nil {
		return nil, err
	}
	out, held, err := c.fetchRange(h, ph, start, end, keys != nil)
	c.close()
	if err != nil {
		return nil, c.result(err)
	}
	return openAllHeld(ctx, out, held, h, keys)
}

// FetchKeys gets the entry keys of the entries start to end, end included, from a peer with Keys access,
// without their ciphertexts; element i is the key of entry start+i, or nil where the peer gave none.
func FetchKeys(ctx context.Context, conn Conn, h kololog.VerifiedHead, start, end uint64) ([]kololog.EntryKey, error) {
	c, ph, err := openRange(ctx, conn, h, start, end)
	if err != nil {
		return nil, err
	}
	defer c.close()
	out, err := c.keyRange(h, ph, start, end)
	if err != nil {
		return nil, c.result(err)
	}
	return out, nil
}

// openRange checks the arguments of a range call and opens its stream.
func openRange(ctx context.Context, conn Conn, h kololog.VerifiedHead, start, end uint64) (*client, kololog.Head, error) {
	if noConn(conn) {
		return nil, kololog.Head{}, ErrInvalidArgument
	}
	// A zero head has size 0, so every range is past it.
	if start > end || end >= h.Size() {
		return nil, kololog.Head{}, fmt.Errorf("%w: entries %d to %d of a head of %d: %w", ErrInvalidArgument, start, end, h.Size(), kololog.ErrOutOfRange)
	}
	c, ph, _, err := open(ctx, conn, h.LogKey(), h.LogID())
	return c, ph, err
}

// covers checks that the peer's head ph holds the entries of h.
func covers(h kololog.VerifiedHead, ph kololog.Head) error {
	theirs, err := kololog.VerifyHead(h.LogKey(), h.LogID(), ph)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case theirs.Size() < h.Size():
		return fmt.Errorf("%w: the peer's head has %d entries, %d asked", ErrBehind, theirs.Size(), h.Size())
	case theirs.Size() == h.Size() && theirs.Root() != h.Root():
		return fmt.Errorf("%w: two heads of %d entries", ErrDiverged, h.Size())
	}
	return nil
}

// fetchRange gets and checks the entries from start to end; with wantHeld, it also returns those that came
// without a key, for openAllHeld. On an error, it clears the values it got and returns them.
func (c *client) fetchRange(h kololog.VerifiedHead, ph kololog.Head, start, end uint64, wantHeld bool) (out []Fetched, held []heldEntry, err error) {
	if err := covers(h, ph); err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			for _, f := range out {
				clear(f.Data)
			}
		}
	}()
	for next := start; next <= end; next = start + uint64(len(out)) {
		resp, err := c.call(message{typ: tFetchReq, a: next, b: end, size: h.Size()}, tFetch)
		if err != nil {
			return out, nil, err
		}
		out, held, err = opened(out, held, h, resp, next, end, wantHeld)
		wipe(resp)
		if err != nil {
			return out, nil, err
		}
	}
	return out, held, nil
}

// openAllHeld opens the entries in held with the keys the caller holds, and puts the result in out. On an
// error, a panic in keys, or once ctx is done, it clears the values in out and returns no entries.
func openAllHeld(ctx context.Context, out []Fetched, held []heldEntry, h kololog.VerifiedHead, keys func(uint64) (kololog.EntryKey, error)) ([]Fetched, error) {
	done := false
	defer func() {
		if !done {
			for _, f := range out {
				clear(f.Data)
			}
		}
	}()
	for _, x := range held {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := openHeld(h, x.proof, x.entry, keys)
		switch {
		case errors.Is(err, kololog.ErrKeyUnavailable), errors.Is(err, kololog.ErrDeleted), errors.Is(err, ErrKeyMismatch):
			out[x.pos] = Fetched{Index: x.proof.Index, Err: err}
		case err != nil:
			return nil, err
		default:
			out[x.pos] = Fetched{Index: x.proof.Index, Data: data}
		}
	}
	done = true
	return out, nil
}

// heldEntry is an entry that checked out without a key and waits for the key the caller holds.
type heldEntry struct {
	pos   int
	proof kololog.InclusionProof
	entry kololog.Entry
}

// opened appends to out the entries of a FETCH answer to a request from next to end, each checked against h
// and opened with the peer's key. An entry that came without one is reported with kololog.ErrKeyUnavailable,
// and is also added to held if wantHeld is set. On an error, it returns the entries so far for the caller to clear.
func opened(out []Fetched, held []heldEntry, h kololog.VerifiedHead, m message, next, end uint64, wantHeld bool) ([]Fetched, []heldEntry, error) {
	k := uint64(len(m.entries))
	if k == 0 || k > end-next+1 {
		return out, held, fmt.Errorf("%w: %d entries for %d asked", ErrProtocol, k, end-next+1)
	}
	for j, e := range m.entries {
		i := next + uint64(j)
		p, err := kololog.DecodeInclusionProof(m.proofs[j])
		if err != nil {
			return out, held, fmt.Errorf("%w: entry %d: %w", ErrInvalid, i, err)
		}
		// OpenEntry checks the record against the proof's index, so the proof must be for the entry asked.
		if p.Index != i {
			return out, held, fmt.Errorf("%w: proof of entry %d for entry %d", ErrInvalid, p.Index, i)
		}
		data, err := kololog.OpenEntry(h, p, e)
		switch {
		case errors.Is(err, kololog.ErrKeyUnavailable) && wantHeld:
			held = append(held, heldEntry{pos: len(out), proof: p, entry: e})
			out = append(out, Fetched{Index: i, Err: err})
		case errors.Is(err, kololog.ErrDeleted), errors.Is(err, kololog.ErrKeyUnavailable):
			out = append(out, Fetched{Index: i, Err: err})
		case err != nil:
			return out, held, checked(err)
		default:
			out = append(out, Fetched{Index: i, Data: data})
		}
	}
	return out, held, nil
}

// openHeld opens e, which has checked out without a key, with the key the caller holds for it:
// kololog.ErrKeyUnavailable if it holds none, kololog.ErrDeleted if the caller knows the entry is deleted,
// ErrKeyMismatch, or an error that fails the call.
func openHeld(h kololog.VerifiedHead, p kololog.InclusionProof, e kololog.Entry, keys func(uint64) (kololog.EntryKey, error)) ([]byte, error) {
	key, err := keys(p.Index)
	defer clear(key)
	switch {
	// Log.Key and Replica.Key: ErrOutOfRange for an entry past the caller's own copy.
	case errors.Is(err, kololog.ErrKeyUnavailable), errors.Is(err, kololog.ErrOutOfRange):
		return nil, kololog.ErrKeyUnavailable
	case errors.Is(err, kololog.ErrDeleted):
		return nil, kololog.ErrDeleted
	case err != nil:
		return nil, fmt.Errorf("kolosync: key of entry %d: %w", p.Index, err)
	case len(key) == 0:
		return nil, kololog.ErrKeyUnavailable
	}
	e.Key = key
	data, err := kololog.OpenEntry(h, p, e)
	if errors.Is(err, kololog.ErrBadEntry) {
		// The entry checked out without the key, so the key is what does not match.
		return nil, fmt.Errorf("%w: entry %d: %w", ErrKeyMismatch, p.Index, err)
	}
	return data, checked(err)
}

// keyRange gets the keys from start to end; on an error, it zeroes the keys it got before returning them.
func (c *client) keyRange(h kololog.VerifiedHead, ph kololog.Head, start, end uint64) (out []kololog.EntryKey, err error) {
	if err := covers(h, ph); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			for _, k := range out {
				clear(k)
			}
		}
	}()
	for next := start; next <= end; {
		resp, err := c.call(message{typ: tStateReq, a: next, b: end, keys: true}, tState)
		if err != nil {
			return out, err
		}
		if err := stateEnd(resp.a, next, end); err != nil {
			wipe(resp)
			return out, err
		}
		for range resp.a - next {
			out = append(out, nil)
		}
		// decode has checked that the items are in ascending order, each index once.
		for _, it := range resp.items {
			if it.index < next || it.index >= resp.a {
				wipe(resp)
				return out, fmt.Errorf("%w: state item out of range", ErrProtocol)
			}
			if it.key != nil {
				out[it.index-start] = slices.Clone(it.key)
			}
		}
		wipe(resp)
		next = resp.a
	}
	return out, nil
}

// stateEnd checks the end a of a STATE answer to a request from next to end: past next, within the range, and
// no further than one answer may scan, so the slots added for it are bounded.
func stateEnd(a, next, end uint64) error {
	if a <= next || a > end+1 || a-next > maxScan {
		return fmt.Errorf("%w: state ends at %d", ErrProtocol, a)
	}
	return nil
}
