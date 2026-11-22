# Limits

Every fixed bound in kolo-sync, with its value and reason. A message or answer larger than a bound is refused with the error named in [guide.md](guide.md#errors).

| Limit | Value | Why |
|---|---|---|
| `MaxMessageSize` | 4 MiB, a common default for the largest received message, length prefix checked before allocating | Memory: bounds every buffer. An entry whose padded ciphertext does not fit cannot be synced or fetched (`ErrTooLarge`), deleted or not, and the log does not sync past it; the server checks the record's size and never reads such an entry. A FETCH answer also carries one proof per entry (at most 64 hashes); every entry that fits in ENTRIES fits in FETCH too, since kolo-log pads values near 4 MiB to steps of 64 KiB |
| `MaxStreams` (streams served at once per connection) | 16, more are answered busy | Memory: equal to kolo-transport's default stream limit |
| `ServerOptions.MaxTotalStreams` (streams served at once over all connections) | 256 (`DefaultMaxTotalStreams`, 16 connections of `MaxStreams`), more are answered busy | Memory and work: nothing else bounds the streams of many connections or of many keys; the per-connection limit alone allows 16 for each of kolo-transport's 100 connections |
| `ServerOptions.MaxAnswerBytes` (answers being built or written, over all connections) | 256 MiB (`DefaultMaxAnswerBytes`), at least 2 × `MaxMessageSize`; an answer that does not fit is refused busy | Memory: a quarter of kolo-transport's default `MaxMemory` (1 GiB). An answer counts twice its size, the entries read from the log and the frame built from them; room for a 1 MiB answer is reserved before the log is read, and the count grows to the answer's real size |
| `Timeout` (opening a stream, the wait for the next request, the start of each message read or write, and each `MinProgress` bytes of a message after that) | 60s, a common server default for the time between two reads | Security: a silent peer holds a stream for at most this long. A message that keeps moving is never cut off, however slow the path: a 1 MiB answer at 2 KB/s takes about 9 minutes and arrives |
| `MinProgress` | 16 KiB within every `Timeout`, for a message read | The slowest a message may arrive, 16 KiB a minute (about 273 bytes a second); a reader cuts off a peer that trickles less after one `Timeout` |
| Whole message written | `Timeout` plus its size at 500 bytes a second: about 36 minutes for 1 MiB, 2.4 hours for 4 MiB | Memory: the server holds an answer until it is written, so a peer that barely reads is cut off; it can pin `MaxAnswerBytes` (256 MiB, 128 answers of 1 MiB counted twice) only by reading at least 64 KB/s in all. 500 bytes a second is the default body rate of Apache's mod_reqtimeout |
| `ServerOptions.MaxWatched` (distinct logs one connection may watch) | 1024 (`DefaultMaxWatched`), at least 55; past it the watch stream is answered ERROR 3 | Memory and work: the heads of 1024 logs fit in one or two WATCH messages even at the largest legal head (`MaxMessageSize` / 4 KiB), and a stream's list is scanned when a log grows |
| `ServerOptions.WatchGap` (least time between two WATCH messages on a stream, and between two probes of the watched logs) | 100 ms, 10 ms to 10 s | Work: a flood of appends costs one push per gap, and the server signs one head per log per growth |
| Watch streams | one per connection, taking one of its `MaxStreams` slots; at most `MaxTotalStreams` over a server, counted apart from the streams that serve pulls | Memory: idle watchers must not starve pulls; no idle deadline, a dead connection ends at kolo-transport's idle timeout (30 s) |
| WATCH_REQ items | 55 per request | A request is at most 4 KiB: (4096 - 3) / (32 + 32 + 10), the largest encoding of an item |
| Request size | 4 KiB at most, checked with the length before the body is read | Memory: a request is a few dozen bytes, so a larger length is refused at once (`ErrTooLarge`) and no buffer is held for a body that trickles |
| Answer to a request for entries | about 1 MiB | An entry larger than that goes alone, up to `MaxMessageSize` |
| `DefaultInFlight`, `MaxInFlight` (`PullOptions.InFlight`) | 3, 1 to 8 | Speed: for a peer that does not stream, how many answers a pull has asked for and not stored, 3 if 0; for a peer that streams, how many requests of credit it keeps waiting at most, 8 if 0. Any other value is `ErrInvalidArgument` |
| Credit of a streamed pull | 2 MiB a request; the pull keeps from 2 requests up to `InFlight` waiting; the peer holds at most 64 MiB of credit for one stream and refuses a request of more | Memory and work: credit is what the peer may send before it needs more, so it bounds the answers on their way, the work wasted when a pull stops, and what is read and dropped to free the stream. The pull's request count follows twice the bandwidth-delay product it measures, between 2 and `InFlight` requests, so the credit waiting is more than 2 MiB and at most 4 MiB at first, and at most 16 MiB with `InFlight` 8 |
| Answers a pull holds that are not stored yet | 6 MiB of messages at most, and one message is always admitted, so a 4 MiB one is held | Memory: the reader waits for room before it reads a message, once its length is checked against `MaxMessageSize`, so `InFlight` times `MaxMessageSize` is never held and a hostile peer cannot make a pull hold more; about 5 answers of 1 MiB fit, 2 of 2 MiB or 1 of 4 MiB do |
| Answers one commit stores | the answers that wait, until they reach 4 MiB, at least one | One sync of the store for them all instead of one each; a failed commit stores them one at a time |
| entries one STATE answer looks at | 32768 (`MaxMessageSize` / 128, as many entries as one ENTRIES answer can hold), then it stops early | CPU: a small request costs the server at most as many entries as an ENTRIES or FETCH request; it reads only the delete markers and keys it sends, never a ciphertext |

A pull of a replica therefore holds up to 6 MiB of answers, about 5 answers of 1 MiB when they arrive faster than they are
stored; `Replica.Update` copies the answers of one commit. This bound is the same for a peer that streams and one that does not, and does
not grow with the credit or with the round trip: the reader takes no message off the stream until the gate has room for it,
so the credit that is waiting is data on its way or in the transport's receive windows, which kolo-transport bounds
(its `MaxStreamReceiveWindow` and `MaxConnReceiveWindow`), and that a peer that sends faster than the pull stores waits in them,
which makes its own writes wait. Worst case, a pull holds 6 MiB of answers, or one answer of up to 4 MiB if that is more, plus the
decoded copy of the answer it is reading; the server holds about two copies of one answer (the entries read from the log and the frame built from them, up to 8 MiB for a 4 MiB answer) for each stream it is writing to, however much credit the peer sends. Over all
connections that is bounded by `MaxAnswerBytes` and `MaxTotalStreams`, whatever the number of peers; a stream or an answer past them is answered busy, and `ServerStats.RefusedByLimit` counts them. When a pull asks for one answer at a time, at most
`InFlight` requests for entries wait at the peer, whose server reads them one at a time.

A request for credit (STREAM_REQ, CREDIT_REQ) of a few bytes costs the server the answers it pays for, up to 64 MiB of the log
(about 64 answers of 1 MiB, each with a consistency proof) as fast as the peer reads them, not one message: the work is bounded
by the peer's read speed and the 64 MiB of credit, not by its number of requests. It needs no more memory than one answer
at a time: it builds one answer, writes it, and only then builds the next. A peer that asks for credit and never
reads is cut off at the write deadline of the answer it does not read, `Timeout` plus the answer's size at 500 bytes a second, as a peer
that asks for an answer and never reads it.

`Fetch` keeps the values of the range it was asked for, so its memory is
that of the range the caller chose, at most one message more;
`FetchWithKeys` also keeps each entry that came without a key until the
call returns, so up to about twice that; a peer cannot make them hold more, since every value is
checked against its signed record. `FetchKeys` holds one slot per entry
asked and 32 bytes per key, also the caller's range.

`FetchWithKeys` opens each held entry after the stream is closed (a second
check of its record, proof and ciphertext, then the decryption), so the time it
takes to return grows with the number of held entries and their size.
