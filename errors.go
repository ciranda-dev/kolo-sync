package kolosync

import "errors"

var (
	// ErrInvalidArgument means a nil connection, replica, source or key, a key of the wrong size, a zero head,
	// a Fetch, FetchWithKeys or FetchKeys range that is empty or past the head (wrapping kololog.ErrOutOfRange),
	// or a PullOptions.KeysFrom past the replica's length.
	ErrInvalidArgument = errors.New("kolosync: invalid argument")
	// ErrNotFound means the peer does not serve the log to us: it does not have it, did not offer it, or did not authorize us.
	ErrNotFound = errors.New("kolosync: log not found")
	// ErrDiverged means the owner signed two histories: the peer's signed head or record conflicts with ours or with the head
	// Fetch, FetchWithKeys or FetchKeys checks against. Neither log was changed.
	ErrDiverged = errors.New("kolosync: logs diverged")
	// ErrInvalid means the peer sent a head, proof, entry, marker or key that does not verify; a kolo-log error is wrapped too.
	ErrInvalid = errors.New("kolosync: peer sent data that does not verify")
	// ErrProtocol means a malformed, truncated or unexpected message, or another protocol version.
	ErrProtocol = errors.New("kolosync: protocol error")
	// ErrTooLarge means a message over MaxMessageSize, or an entry too large to fit in one.
	ErrTooLarge = errors.New("kolosync: message too large")
	// ErrBehind means the peer's head has fewer entries than the head Fetch, FetchWithKeys or FetchKeys checks against,
	// or, for PullWith with NoMarkers, than the head the replica is filling toward (after ErrMarked); no entry or key is added.
	ErrBehind = errors.New("kolosync: peer is behind the head")
	// ErrKeyMismatch, in Fetched.Err, means a key given to FetchWithKeys does not match its entry's record.
	ErrKeyMismatch = errors.New("kolosync: held key does not match its record")
	// ErrBusy means the peer refused the stream or an answer (MaxStreams, ServerOptions) or could not read its log, or another Pull of the replica is running.
	ErrBusy = errors.New("kolosync: peer busy")
	// ErrMarked means the peer serves a deleted entry to a PullWith with NoMarkers; the replica then holds
	// only the entries before it, so its Len is that entry's index.
	ErrMarked = errors.New("kolosync: peer serves a deleted entry")
	// ErrTimeout means a message read or write took longer than Timeout.
	ErrTimeout = errors.New("kolosync: timeout")
)
