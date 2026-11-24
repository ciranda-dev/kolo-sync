# Guide

The full API of kolo-sync, how it fails and why it works the way it does. Bounds are in [limits.md](limits.md); the wire format and the standards it follows are in [protocol.md](protocol.md).

## API

A log is named by its owner's public key and its log ID, everywhere: in
`Offer` and `Withdraw`, in `authorize`, and on the wire. Two owners' logs
with the same log ID are two different logs, so one owner can neither
replace nor withdraw another's log by reusing its ID.

- `Conn` is the connection every call takes: `RemotePublicKey`,
  `OpenStream` and `AcceptStream`. A `*kolosecure.Conn` and a
  `koloswarm.Conn` satisfy it, so sync works over direct and relayed
  connections alike. `RemotePublicKey` must return the key the peer proved
  in the end-to-end handshake; a relayed link proves it the same way as a
  direct one, so `authorize` sees the same key. A nil `Conn`, or one that
  holds a nil pointer, is `ErrInvalidArgument`, and `Serve` refuses a
  `Conn` whose key is not 32 bytes with `ErrInvalidArgument`.

- `NewServer(authorize) *Server` returns a server with no offered logs;
  `NewServerWith(authorize, *ServerOptions)` also sets the limits it applies over all
  its connections, `MaxTotalStreams` (default 256) and `MaxAnswerBytes` (default 256 MiB): a stream or an
  answer past either is answered busy, and the client's call returns `ErrBusy`.
  See [limits.md](limits.md).
  `authorize(peer, owner, logID) Access` gets the peer's kolo-id public
  key and the requested log's owner key and log ID, on every request of a
  stream, for any log, so a revoked peer stops at its next request. It
  returns:
  - `NoAccess`: the peer gets the answer of a log we do not have.
  - `Ciphertext`: records, proofs, ciphertexts and delete markers, but no
    entry keys. The peer can keep and serve a verified copy it cannot read.
  - `Keys`: all of the above and the entry keys.

  Either access also lets the peer make us read up to `MaxMessageSize` of
  the log per small request, with no rate bound, so grant `Ciphertext` or
  `Keys` only to peers you trust with that load.

  A nil `authorize`, a panic or any other value means `NoAccess`. It must
  be fast and safe for concurrent use.
- `Offer(src) error` makes a log available under its owner key
  (`src.Header().LogKey`) and log ID (`src.ID()`), replacing an earlier
  source with both the same. It refuses a nil source (`ErrInvalidArgument`)
  and one whose header is not signed by that owner or names another log
  ID than `src.ID()` (`ErrInvalidArgument` wrapping
  `kololog.ErrBadLogHeader`). Past that it trusts `src` to serve that
  owner's log; a client still checks every head, entry and proof against
  the owner's key. After `Withdraw(owner, logID)`, requests
  for that log get the answer of a missing log. A `Source` is a kolo-store `*Log` or
  `*Replica`, or a kolo-log `*Log` or `*Replica`, so a peer serves logs it
  owns and replicas it holds alike: `ID`, `Header`, `Head`, `Record`,
  `Entry`, `EntryInfo`, `Key`, `InclusionProof` and `ConsistencyProof`. A replica serves its
  last fully held head.
- `Stats() ServerStats` returns the server's totals over all connections,
  read with atomics: `BytesSent`, every frame byte written, answers of
  every kind included (pulls and fetches alike), and `ActiveStreams`, the
  streams being served now, pull and fetch streams alike (refused ones not
  counted), `RefusedByLimit`, the streams and answers refused by `MaxTotalStreams` or
  `MaxAnswerBytes`, and `AnswerBytes`, the memory the answers in flight hold now.
  There is nothing per peer or per log.
- `Serve(ctx, conn)` answers the streams the peer opens on a
  `Conn`, for `Pull`, `PullCiphertext`, `FetchHeader`,
  `FetchHead`, `Fetch`, `FetchWithKeys` and `FetchKeys` alike, until `ctx` is done (`ctx.Err()`) or the connection
  ends (its error), then waits for the streams it started. It must be the
  only caller of `conn.AcceptStream`. Run one per connection.
- `Pull(ctx, conn, rep)` brings a `*kolostore.Replica` up to date with the
  peer's copy of its log, checked against the owner key in the replica's
  header, then applies the peer's delete markers and, if the peer gives
  them, the entry keys: those `rep` lacks are added, and one for an entry
  `rep` already holds with its key must be that key, or the pull fails
  with `ErrInvalid`. Returns nil when the peer is behind or even,
  also when it is behind the head an interrupted pull was filling. A
  second `Pull` of a replica while one runs returns `ErrBusy`; pulls of
  different replicas may run at once on one connection.
- `PullCiphertext(ctx, conn, rep)` is `Pull` for a peer that must never
  hold entry keys, such as a pinning node: it never asks for keys and never
  calls `AddKey`, and an answer that carries a key anyway is `ErrProtocol`,
  with nothing from it stored. Markers still arrive.
- `PullWith(ctx, conn, rep, opts) (PullResult, error)` is `Pull` with
  `*PullOptions`; nil or the zero value pulls as `Pull` does and sends the
  same messages. See [Pulling without delete markers](#pulling-without-delete-markers),
  [Answers in flight](#answers-in-flight) and [Pull statistics](#pull-statistics).
- `FetchHeader(ctx, conn, owner, logID)` returns the log's signed header,
  checked against `owner`, to open a new replica with
  `Store.OpenReplica`.
- `FetchHead(ctx, conn, owner, logID) (kololog.VerifiedHead, error)`
  returns the peer's signed head of the log, verified against `owner` and
  `logID`, for a client that holds no head yet. It is the owner-signed
  head this peer holds, which may be older than the newest one or one side
  of a fork; `Fetch` against it is correct for that head.
- `Fetch(ctx, conn, h, start, end) ([]Fetched, error)` gets the entries
  `start` to `end`, `end` included, of the log of `h` (a
  `kololog.VerifiedHead`) from the peer, without a replica, in as many
  messages as they need. Each entry comes with its inclusion proof in the
  tree of `h`'s size and goes through `kololog.OpenEntry`, which checks
  the proof, the record's signature and index, the ciphertext or delete
  marker and the key against its commitment before it decrypts. A
  `Fetched` is `Index`, `Data` (the value, as `Get` returns it) and
  `Err`: nil, `kololog.ErrDeleted` for an entry with a verified delete
  marker, or `kololog.ErrKeyUnavailable` when the peer gave no key (it
  gives us no `Keys` access, does not hold the key, or chose not to send
  it; the client cannot tell these apart, so ask another peer that gives
  `Keys` access, or hold the keys and use `FetchWithKeys`). A peer can also leave out a delete marker and serve the
  live entry, since deletion is best effort, but it can never make a live
  entry look deleted without the owner's signed marker. Any other
  failure fails the whole call and returns no entries. `h` is the head the
  client trusts: one it holds, such as its replica's verified head, or
  `FetchHead`'s. A range past `h` is `ErrInvalidArgument` wrapping
  `kololog.ErrOutOfRange`. Many fetches may run at once on one
  connection, each on its own stream.
- `FetchWithKeys(ctx, conn, h, start, end, keys) ([]Fetched, error)` is
  `Fetch` for a client that holds entry keys, such as one reading from a
  pinning peer that serves ciphertext only. `keys(index)
  (kololog.EntryKey, error)` returns the key the client holds for an
  entry. It is asked only for a live entry whose answer carries no key,
  after the entry, its record and its proof checked out;
  `FetchWithKeys` zeroes the key after use, so `keys` returns a copy. A
  nil or empty key, or an error wrapping `kololog.ErrKeyUnavailable`, means no key
  is held: the entry is reported with `kololog.ErrKeyUnavailable`, so
  `Log.Key` and `Replica.Key` fit as `keys` (their `kololog.ErrOutOfRange`
  counts as none held, and their `kololog.ErrDeleted` reports the entry as
  deleted). Any other error from `keys` fails the call and is wrapped. A key that does
  not match the record's key commitment decrypts nothing, and that entry alone is reported with
  `ErrKeyMismatch`; the others are opened. `keys` is asked only after the
  last answer has arrived and the stream is closed, so neither the pace
  nor the end of the stream tells the peer whether the client holds keys
  or whether they match. Nothing on the wire changes with the keys, but
  the time `FetchWithKeys` takes to return does: it opens the held
  entries after the stream ends, so a peer that sees the client's next
  request on the same connection can tell from its timing whether keys
  were held and whether they matched. What the application does next
  (such as stopping after a mismatch) the peer can also see. Once `ctx`
  is done no more keys are asked. On any error, and if `keys` panics (the
  panic goes on to the caller), the values already opened are cleared
  and no entries are returned. `Fetch` is
  `FetchWithKeys` with no `keys`.
- `FetchKeys(ctx, conn, h, start, end) ([]kololog.EntryKey, error)` gets
  the entry keys of the entries `start` to `end`, `end` included, from a
  peer that gives us `Keys` access, without their ciphertexts. Element
  `i` is the key of entry `start+i`, or nil where the peer gave none (a
  deleted entry, a key it does not hold, or no `Keys` access: these look
  the same). The peer's head is checked against `h` as in `Fetch`. A key
  is checked against its signed record when `FetchWithKeys` uses it;
  kolo-log has no check of a key without the ciphertext. Clear the keys
  when done. The slice has one element per entry asked, so its size is
  the range the caller chose.

Reading from a pin while the owner is offline: the reader gets a head
(`FetchHead`) and the keys of the entries it will read (`FetchKeys`) from
the owner or another peer with `Keys` access, and keeps them; where is up
to the application. Later it reads the entries from a pin with
`FetchWithKeys` and a `keys` function over what it kept. The keys never
leave the reader: the pin gets the same FETCH_REQ as for `Fetch`, so it
learns which indexes are read and the size of the reader's head, as with
any fetch, and nothing about the keys beyond the key commitment it already
holds in each signed record. The pin needs no key material.

Both ends may serve and pull on one connection. Entry keys travel only on
the kolo-secure connection, never in an error or a log line.

## Answers in flight

A pull asks for the entries once and keeps the link full. Its
first request for entries, STREAM_REQ, names where to start and gives credit in bytes; the peer then
sends each answer of about 1 MiB, followed by the proof of where it ends, without waiting for
another request, as long as the credit lasts, and the pull sends more credit (CREDIT_REQ) before
it is used up. One goroutine reads the stream, and the caller's goroutine verifies and stores
the answers in order with `Replica.Update`, so the replica only ever grows by verified answers,
in order. Asking one answer at a time sends the next request only when the first bytes of the
answer before it arrive, and so moves about one answer, 1 MiB, for each round trip, whatever the
link can carry: 10 MB/s at 100 ms. A streamed pull moves what the transport's window and the
link allow. The wire format is in [protocol.md](protocol.md#streamed-entries).

- `InFlight` bounds the requests of credit, 2 MiB each, that are waiting at the peer, 1 to `MaxInFlight`
  (8), so at most 16 MiB of answers are on their way (4 MiB when it keeps 2); any other value is `ErrInvalidArgument`. The
  pull keeps 2 of them waiting, so the peer always has the next answer to send, and more as it measures
  the round trip (the time of its first requests) and the speed it reads at: twice the bandwidth-delay
  product, in requests, up to `InFlight`. 0 is `MaxInFlight`, which only says how far it may go: a path
  with a short round trip keeps 2 and one with a long round trip and a fast link keeps more. With 1, the pull
  asks again only after the credit before is used up. A pull never holds more than 6 MiB of answers that are not
  stored, whichever the number is; the credit waiting is the peer's answers on the wire, in the transport's
  windows, not in the pull's memory.
- A peer that does not stream answers STREAM_REQ with an error and closes the stream, and
  the pull opens another stream and asks for each answer with one request and one proof, up to `InFlight`
  requests ahead (0 is `DefaultInFlight`, 3, and 1 asks for each answer after the one before is stored). It costs two
  round trips in each pull that has entries to get. `PullStats.Streamed` says which form a pull had. A server also serves a
  pull that asks for one answer at a time.
- Answers that are already waiting when one is stored go into the same
  `Update`, one commit and one sync of the store, up to 4 MiB of answers; if
  that `Update` fails, the answers are stored one at a time, so the entries
  stored before a bad answer, and the error, are the same as when each is stored alone. The proof of an answer that is not the
  last of its commit is read and not used: the last proves the entries before it, so a bad
  proof there costs nothing and does not fail the pull.
- A failure, a hostile answer or a cancel at any point leaves the replica as
  it is after the last answer that was stored whole, with no head until the
  pull completes, and `rep.Len()` is where the next `Pull` resumes. The
  answers that had arrived whole before a failure, such as a lost connection,
  are stored first. Errors, `ctx` and the per-message deadlines are as
  with one request at a time: every message may take as long as it needs while
  each `MinProgress` bytes of it move within `Timeout`, and a done `ctx` returns `ctx.Err()`. A peer that stops sending in
  the middle of the credit is `ErrTimeout`.
- The answers a pull holds that are not stored yet never pass 6 MiB, whatever
  `InFlight` is; see [limits.md](limits.md). A pull with answers of 1 MiB
  holds up to 5 of them.

The window kolo-transport gives a stream still bounds one stream to its window per round trip, so
what a pull reaches is the smaller of that and the link: a stream window of 4 MiB is about 40 MB/s
at 100 ms and 20 MB/s at 200 ms. Raising the transport's window ceilings (kolo-transport's
`MaxGrownStreamReceiveWindow` and `MaxGrownConnReceiveWindow`) is how a pull goes faster than that.
`InFlight` needs no change for it: 8 requests are 16 MiB.

## Pull statistics

`PullResult.Stats` says where the time of a `PullWith` went, also when it failed. For the numbers while it
runs, give `PullOptions.Meter` a `*PullMeter` (its zero value is ready) and call `Meter.Stats()` from any
goroutine, as often as you like; the last snapshot is the result's. A meter measures one pull at a time: a pull that starts with a meter another pull is using returns `ErrInvalidArgument`, and one that starts after the last has ended resets it.

| Field | Meaning |
|---|---|
| `Streamed` | the peer streamed the entries; false for a peer that does not know STREAM_REQ |
| `Elapsed` | time since the pull started, or its length once it ended |
| `Bytes`, `Entries`, `Answers`, `AvgAnswer()` | ENTRIES answers read: message bytes, entries, messages, average size |
| `Received` | message bytes of ENTRIES answers taken off the stream so far, also of the one being read: a progress count that moves with the bytes, while `Bytes` moves once per answer |
| `Requests` | requests for entries sent |
| `ReaderWait` | time the reader spent reading answers, waiting for their bytes, not counting memory waits |
| `CommitBusy`, `CommitIdle` | time the goroutine that verifies and stores spent doing it, and waiting for an answer |
| `FirstByteMin`, `FirstByteAvg`, `FirstByteMax` | from writing a request for entries to the first bytes of its answer; one sample per request when asking one answer at a time, one per fill (the STREAM_REQ) when streaming |
| `InFlightMax`, `InFlightAvg` | requests for entries waiting, most and average over time |
| `InFlightBlocked` | times `InFlight` held a request back |
| `MemoryBlocked`, `MemoryWait`, `HeldMax` | times the reader waited for room under the 6 MiB, the time it waited, and the most bytes of answers held |

Reading them: `CommitIdle` near `Elapsed` and `ReaderWait` near `Elapsed` mean the pull waits for the peer
or the network, not for this machine; with `Streamed` true and `FirstByteMin` near the round trip, that
is the link or the transport's window (bytes per second times the round trip near the window). `CommitBusy` near
`Elapsed` means the machine verifies and stores as fast as it can. `MemoryBlocked` rising with `CommitBusy`
high means the store is the slower side. `FirstByteMin` far above the round trip means the peer is slow to
read its log. `Streamed` false means the peer does not stream: `Bytes` per `FirstByteMin` is then the rate of one answer per
round trip. The meter takes a mutex a few times for each answer and costs about 60 ns an answer (`BenchmarkMeter`), against the milliseconds an answer of 1 MiB takes to arrive.

## Pulling without delete markers

`PullOptions` has four fields; `NoMarkers` and `KeysFrom` are described here, `InFlight` [above](#answers-in-flight) and `Meter` under [Pull statistics](#pull-statistics):

- `NoMarkers`: the pull neither requests nor stores delete markers, so a
  peer that deleted entries, or claims it did, cannot erase them from the
  replica. An ENTRIES answer is checked before anything is stored: at its
  first entry that carries a marker, only the entries before it go to
  `Replica.Update`, with one more PROOF request for that shorter prefix so
  the replica stays verified, and the pull returns `ErrMarked` naming that
  index. `rep.Len()` is then that index, and the replica fills toward
  that peer's head: pull the rest from a peer whose head is at least as
  large. A peer behind that head adds nothing and returns `ErrBehind`
  (`Pull` returns nil there).
  The marker is never decoded or checked, so a forged one stops the pull
  the same way. STATE markers are ignored, also bad or misplaced ones, and
  no STATE request asks for markers alone; the keys in STATE answers are
  checked and added as in `Pull`. A marker already in the replica stays.
- `KeysFrom`: the first index the caller may hold without its key. The
  local scan for missing keys and the STATE requests for keys start there.
  With `NoMarkers` a pull then costs the new entries and the entries still
  without a key, not the whole log; without it the delete markers are
  still asked from index 0. A value past `rep.Len()` is `ErrInvalidArgument`.

`PullResult.KeysFrom` is the first index still held without its key after
the pull (deleted entries are passed over), or `rep.Len()` when every
entry has its key: keep it with the replica and give it to the next pull.
On an error it is `opts.KeysFrom`, so the cursor never skips an entry.

A pull that tries the next peer when one serves a deleted entry or is
behind the head the replica fills toward:

```go
func pullLive(ctx context.Context, peers []kolosync.Conn, rep *kolostore.Replica, keysFrom uint64) (uint64, error) {
	err := kolosync.ErrNotFound
	for _, conn := range peers {
		var res kolosync.PullResult
		res, err = kolosync.PullWith(ctx, conn, rep, &kolosync.PullOptions{NoMarkers: true, KeysFrom: keysFrom})
		if err == nil {
			return res.KeysFrom, nil
		}
		if !errors.Is(err, kolosync.ErrMarked) && !errors.Is(err, kolosync.ErrBehind) {
			return keysFrom, err
		}
		// rep holds the entries before the deleted one; the next peer goes on from rep.Len().
	}
	return keysFrom, err
}
```

The same function is compiled with the tests (`example_test.go`).

## Errors

Errors work with `errors.Is`; none carries bytes a peer sent, only numbers such as sizes and indexes.

- `ErrNotFound`: the peer does not have the log, did not offer it, or did
  not authorize us, or offers that log ID only under another owner. These
  look the same on the wire.
- `ErrDiverged`: the owner signed two histories: a signed head or record
  from the peer conflicts with ours, or with the head `Fetch`,
  `FetchWithKeys` or `FetchKeys` checks against. Neither copy was changed. A bad proof without such evidence is
  `ErrInvalid`, since any peer can send one.
- `ErrBehind`: `Fetch`, `FetchWithKeys` and `FetchKeys`: the peer's
  head has fewer entries than the head the call checks against, so the
  peer cannot prove them or does not hold them. `PullWith` with
  `NoMarkers`: the peer's head has fewer entries than the head the
  replica fills toward, so no entry or key is added. Ask another peer, or
  a later one.
- `ErrMarked`: `PullWith` with `NoMarkers` only: the peer serves a deleted
  entry, or one with a marker, where the replica needs a live one. The
  replica holds the entries before it, so `rep.Len()` is its index, which
  the error message also names. Pull the rest from another peer whose
  head reaches that peer's head.
- `ErrKeyMismatch`: `FetchWithKeys` only, in `Fetched.Err`: a key from
  `keys` does not match its entry's signed record (`kololog.ErrBadEntry`
  is wrapped too). The peer's data checked out against the signed
  record; the held key does not match the record's key commitment, or
  the entry does not decrypt with it.
- `ErrInvalid`: a head, proof, entry, marker or key that does not verify.
  The kolo-log error is wrapped too (`kololog.ErrBadEntry`,
  `kololog.ErrInvalidHead`, ...). The replica keeps what it held.
- `ErrProtocol`: a malformed, truncated or unexpected message, or another
  version.
- `ErrBusy`: the peer refused the stream or an answer (`MaxStreams`, `MaxTotalStreams`, `MaxAnswerBytes`) or could not read its log, or
  another `Pull` of the replica is running; try again later.
- `ErrTooLarge`, `ErrTimeout`,
  `ErrInvalidArgument`.

## Design

- The puller states what it holds by what it asks for. It never sends its
  own head. The server never writes.
- The peer's head is verified (signature, context `kolo-log/tree-head/v0`,
  owner key, log ID) before any other message is read, and proofs are
  checked only against verified heads.
- If the peer is ahead, the puller asks for the consistency proof from its
  head to the peer's head. If it does not verify, the puller asks for the
  peer's record at its last index: an owner-signed record that differs
  from ours proves a fork (`ErrDiverged`); otherwise the proof was bad
  (`ErrInvalid`). Then it fetches the missing range one message at a
  time, each chunk with the proof from its end to the peer's head, and
  gives each chunk to `Replica.Update`, which checks every record
  signature, ciphertext hash, key commitment and the rebuilt root before
  it stores anything.
- A pull that stops in the middle leaves the replica a target: the head
  it was filling, kept across restarts by kolo-store. The next pull from a
  peer that is past the target fills up to the target first, with proofs
  to the target's size, then goes on to the peer's head. A peer whose head
  is below the target is behind, and the pull returns nil, unless its
  owner-signed record at our last held index differs from ours, which is
  `ErrDiverged`.
- Which forks are `ErrDiverged`: a head of a size we hold with another
  root, or an owner-signed record from the peer that differs from ours at
  our last held index. A fork that starts after the entries we hold leaves
  no such evidence: its proofs fail, and the pull returns `ErrInvalid`.
- If the peer is behind or even, the replica checks the peer's head
  against its own tree: a consistent older head is ignored, another root
  is `ErrDiverged`.
- Then state requests walk the entries both hold and return the delete
  markers, and the keys from the first entry the puller holds without its
  key, when the server gives `Keys`. A marker must name the index it is
  listed at. The puller checks every item of a STATE answer first, then
  gives all its markers to one `Replica.ApplyDelete`, which verifies them
  and stores them in one commit, all or none: a bad marker fails the pull
  with `ErrInvalid` and applies none of that answer's markers. Then come
  its keys, one at a time in index order, each checked against its key
  commitment by `Replica.AddKey`; a key equal to the one held stores
  nothing. A key that fails stops the pull with `ErrInvalid`: the answer's
  markers, already verified and signed by the owner, stay applied, the
  keys before it stay added (each verified), and the keys after it are
  not added. `Replica.ApplyDelete` destroys the entry keys and keeps the
  signed records and markers; `Replica.AddKey` checks a late key against
  the key commitment. Both sides find the entries that matter from kolo-log's
  in-memory flags (`EntryInfo`: deleted, key stored) and read only the
  markers and keys themselves (`Entry` of a deleted entry holds no
  ciphertext, `Key` reads the key alone), so a pull with nothing new reads
  no ciphertext on either side. The server looks at most 32768 entries per
  STATE answer; it needs `Ciphertext` or `Keys` access, like any request.
- `authorize` runs before the offered logs are looked at, so a missing, an
  unoffered and an unauthorized log, and a log ID offered only under
  another owner, take one path and give the same bytes.
  A log that is stored but not offered is never read.
- `Fetch` (and `FetchWithKeys` and `FetchKeys`, which check the peer's
  head the same way) checks everything against the head `h` the client
  gives, never against the peer's word. The stream still starts with the peer's signed
  head, checked with `h`'s owner key and log ID: a smaller head is
  `ErrBehind` (it cannot prove inclusion in `h`, and may be an older copy
  or a fork, which nobody can tell from it); a head of `h`'s size with
  another root is `ErrDiverged`; a head of `h`'s size or larger is asked
  for proofs in the tree of `h`'s size, so they verify only if the peer's
  first entries are `h`'s. A peer whose history forked before that size
  fails its proofs, `ErrInvalid` wrapping `kololog.ErrBadProof`, like a
  peer that sends a bad proof. A peer ahead of `h` is fine: no consistency
  proof is needed, since every proof is in `h` itself. To read the newest
  entries, get a newer head first (`FetchHead`, or a `Pull`).
- The client checks that each proof is for the index it asked, since
  `OpenEntry` checks the record against the proof's index: otherwise a
  peer could answer entry 3 with entry 4 and entry 4's valid proof.
- Deletion is best effort. It holds on peers that follow this protocol. A
  peer that already received an entry key can keep it, and old copies of a
  disk can hold a deleted key (see kolo-store).
