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
| Whole message written | `Timeout` plus its size at 500 bytes a second: about 36 minutes for 1 MiB, 2.4 hours for 4 MiB | Memory: the server holds an answer until it is written, so a peer that barely reads is cut off; it can pin `MaxAnswerBytes` (256 MiB, 128 answers of 1 MiB counted twice) only by reading at least 64 KB/s in all. 500 bytes a second (4 kbit/s) is chosen from that memory bound: it is a quarter of the 2 KB/s at which a 1 MiB answer still arrives (above), and at it a peer needs 64 KB/s of reads in all to keep `MaxAnswerBytes` pinned |
| `ServerOptions.MaxWatched` (distinct logs one connection may watch) | 8192 (`DefaultMaxWatched`), at least 55; past it the watch stream is answered ERROR 3 | Memory: the server keeps about 650 bytes for each log a connection names, offered or not (measured, see below), so a connection that names 8192 costs about 5 MiB, less than the 6 MiB one pull may hold. Raise it with `ServerOptions.MaxWatched` for a peer that follows more logs |
| `ServerOptions.MaxWatchBytes` (names watched over all connections) | 64 MiB (`DefaultMaxWatchBytes`, a quarter of `MaxAnswerBytes`), at least 55 names; each name of each connection counts 700 bytes, so 95,869 names; a request past it is answered ERROR 3, as for `MaxWatched`, and counted in `ServerStats.RefusedByLimit`; pulls are not affected | Memory and work: `MaxWatched` alone allows 8192 names for each of `MaxTotalStreams` (256) watch streams, 2 million names or about 1.3 GiB, five times `MaxAnswerBytes`, and a probe of each every `WatchGap`. A name costs 590 bytes at 16,384 names and more (measured, see below), rounded up to 700 and counted for each connection that names it, though connections share the cached head. 95,869 unoffered names cost the server 2.2% of a core at the default `WatchGap`. `ServerStats.WatchBytes` is what is held now. Raise it with `ServerOptions.MaxWatchBytes` for a server with many followers |
| `ServerOptions.PeerBytesPerSecond`, `ServerOptions.PeerBurstBytes` (the bytes of ENTRIES, FETCH and STATE answers one peer key may pull, over all its connections) | 32 MiB a second (`DefaultPeerBytesPerSecond`) and a bucket of 256 MiB (`DefaultPeerBurstBytes`), at least 2 × `MaxMessageSize`; a request that finds fewer than 1 MiB in the bucket, or an answer it cannot pay for, is answered busy (ERROR 2, `ErrBusy`) and counted in `ServerStats.RefusedByLimit`; that stream ends, the peer's other streams, other peers and the memory limits are not affected; zero is the default, a negative value is `ErrInvalidArgument` | Bandwidth: nothing else bounds what one peer may pull over time, so a peer could pull the same large log again and again without end, each copy costing the server the read, the proofs and the send. An answer costs its size (a few dozen bytes over its frame); the cost is taken before the log is read and settled to the real size afterwards, so a refusal reads nothing. A key that took bytes keeps a small record until its bucket is full again (256 MiB at 32 MiB a second, 8 s), then none. A pull of a log larger than the bucket stops with `ErrBusy` and keeps what it stored, and a `Follower` retries it after its backoff. The default rate is 6 times the 5 MiB a second one pull sustained over the 40 ms round-trip path and below the 50 to 110 MiB a second it reached on loopback (see below), and the bucket lets a catch-up of 256 MiB at any speed pass untouched: both values are chosen, on that measured basis, not derived from a spec. WATCH pushes, HEAD and proofs are not counted: they are small and followers depend on them. Raise both fields for a server whose peers legitimately pull more, lower them for a public one (a server of many small logs needs only a small bucket) |
| `ServerOptions.WatchGap` (least time between two WATCH messages on a stream, and between two probes of the watched logs) | 100 ms, at least 10 ms | CPU: one probe of every watched log per gap; measured at 4096 watched logs, a gap of 100 ms uses 2.5% of a core, 10 ms uses 19%, which is why there is no smaller gap. A push arrives within a gap and a few ms. Raise it to save CPU on a server with many watched logs |
| Watch streams | one per connection, taking one of its `MaxStreams` slots; at most `MaxTotalStreams` over a server, counted apart from the streams that serve pulls | Memory: idle watchers must not starve pulls; no idle deadline, a dead connection ends at kolo-transport's idle timeout (30 s) |
| Heads in one WATCH | 256 (1 MiB / 4 KiB, the most a server puts in one WATCH); a follower answers more with `ErrProtocol` | Work: a follower checks one signature for each head, 11.5 ms for 256 heads; 4 MiB could hold 32,263 heads, 1.1 s of one core per message. A head equal to one the peer already offered is not checked again |
| WATCH_REQ items | 55 per request | A request is at most 4 KiB: (4096 - 3) / (32 + 32 + 10), the largest encoding of an item |
| Request size | 4 KiB at most, checked with the length before the body is read | Memory: a request is a few dozen bytes, so a larger length is refused at once (`ErrTooLarge`) and no buffer is held for a body that trickles |
| Answer to a request for entries | about 1 MiB | An entry larger than that goes alone, up to `MaxMessageSize` |
| `DefaultInFlight`, `MaxInFlight` (`PullOptions.InFlight`) | 3, 1 to 8 | Speed: for a peer that does not stream, how many answers a pull has asked for and not stored, 3 if 0; for a peer that streams, how many requests of credit it keeps waiting at most, 8 if 0. Any other value is `ErrInvalidArgument` |
| Credit of a streamed pull | 2 MiB a request; the pull keeps from 2 requests up to `InFlight` waiting; the peer holds at most 64 MiB of credit for one stream and refuses a request of more | Memory and work: credit is what the peer may send before it needs more, so it bounds the answers on their way, the work wasted when a pull stops, and what is read and dropped to free the stream. The pull's request count follows twice the bandwidth-delay product it measures, between 2 and `InFlight` requests, so the credit waiting is more than 2 MiB and at most 4 MiB at first, and at most 16 MiB with `InFlight` 8 |
| Answers a pull holds that are not stored yet | 6 MiB of messages at most, and one message is always admitted, so a 4 MiB one is held | Memory: the reader waits for room before it reads a message, once its length is checked against `MaxMessageSize`, so `InFlight` times `MaxMessageSize` is never held and a hostile peer cannot make a pull hold more; about 5 answers of 1 MiB fit, 2 of 2 MiB or 1 of 4 MiB do |
| Answers one commit stores | the answers that wait, until they reach 4 MiB, at least one | One sync of the store for them all instead of one each; a failed commit stores them one at a time |
| entries one STATE answer looks at | 32768 (`MaxMessageSize` / 128, as many entries as one ENTRIES answer can hold), then it stops early | CPU: a small request costs the server at most as many entries as an ENTRIES or FETCH request; it reads only the delete markers and keys it sends, never a ciphertext |

## Follower bounds

A `Follower` has no limit on the number of logs it follows, connections it follows or peers it follows on: the application chooses its replicas, and no peer can add one. Only the work that peers can ask of it is bounded, and each bound is a field of `FollowOptions`.

| Bound | Default | What it protects, the measured basis, how to raise it |
|---|---|---|
| `MaxPulls` (pulls at once over all connections) | 32 | Memory, since a pull holds up to 6 MiB of answers, so at most 192 MiB, and the peers' work. On a path with a 40 ms round trip, 256 logs of 100 KiB from 8 peers took 40.1 s with 1 pull, 9.5 s with 4, 2.5 s with 16, 1.4 s with 32 and 1.2 s with 64: the step from 16 to 32 saved 43%, from 32 to 64 17%, so 32 is the last doubling that saved more than a quarter. On loopback the time stops falling at 8 (0.68 s) as the processor is the limit. Set `FollowOptions.MaxPulls` to raise it |
| `MaxPullsPerConn` (pulls at once on one connection) | 15, 1 to 15 | The 16 streams a peer's server keeps for a connection (`MaxStreams`), one of which the watch takes, so 15 is the most there is. One log of 64 from one peer: 8 pulls took 1.49 s and 15 took 1.54 s on the 40 ms path, 100 ms and 102 ms on loopback, so more than 8 gains nothing measurable and 15 costs nothing. Lower it with `FollowOptions.MaxPullsPerConn` for a relayed link |
| `RetryMin`, `RetryMax` | 1 s, 10 min; `RetryMin` at least 100 ms | The peers from a retry storm: a failed pull of a log waits `RetryMin` plus a jitter that grows to `RetryMax`. 1 s is the initial retransmission interval RFC 8085 section 3.1.3 recommends for low-rate UDP applications; not measured. Both are `FollowOptions` fields with no upper bound |
| `Poll` | 0 (never), else at least `RetryMin` | The peers' streams: a peer without WATCH is asked for the head of every followed log each `Poll`, one stream per log. Set `FollowOptions.Poll` to turn it on |
| Events | at most 3 per followed log | Memory: only the newest event per log and kind waits; a follower of 4096 logs holds at most 12,288 |

Each followed log costs the follower about 1.8 KB (measured at 256, 1024 and 4096 logs: 1.85, 1.79 and 1.71 KB) with one peer that offers it.

## Measurements

Taken on 2026-11-22 with `go test -run 'TestMeasurePulls|TestMeasureWatch' -v` and `KOLO_SYNC_MEASURE=1` (`limits_test.go`), without `-race`: Apple M5 (10 cores), 24 GiB, macOS 26.7.1, Go 1.27.4 darwin/arm64, 127.0.0.1 only; the 40 ms round trip is a 20 ms one-way delay from `internal/netsim`. Load average (1, 5, 15 minutes) at the start of the runs: 6.3, 5.6, 5.8 and 4.6, 4.2, 4.9; at the end: 3.5, 4.2, 5.1 and 5.2, 4.4, 4.9. Each row is the median of 3 runs of one sync of every log to a fresh follower (1 KiB entries, 100 a log); the heap column, the most heap in use above the start with the collector at 10%, is approximate.

Pulls at once, 256 logs of 8 owners, one connection each:

| MaxPulls | loopback | 40 ms round trip | heap above start (loopback) |
|---|---|---|---|
| 1 | 1601 ms | 40054 ms | 55 MiB |
| 2 | 941 ms | 19801 ms | 55 MiB |
| 4 | 729 ms | 9467 ms | 56 MiB |
| 8 | 681 ms | 4650 ms | 58 MiB |
| 16 | 675 ms | 2458 ms | 61 MiB |
| 32 | 661 ms | 1400 ms | 71 MiB |
| 64 | 706 ms | 1166 ms | 87 MiB |

Pulls at once on one connection, 64 logs from one owner (`MaxPulls` 64):

| MaxPullsPerConn | loopback | 40 ms round trip |
|---|---|---|
| 1 | 295 ms | 9812 ms |
| 2 | 165 ms | 4454 ms |
| 4 | 113 ms | 2291 ms |
| 8 | 100 ms | 1494 ms |
| 15 | 102 ms | 1539 ms |

Watching, one connection that names n logs the server offers; the processor time is the whole program's over 3 s while nothing grows, and the push is the time from an append to its WATCH:

| n | WatchGap | first heads | idle processor | push, median | heap per watched log |
|---|---|---|---|---|---|
| 55 | 10 ms / 100 ms / 1 s | 2 / 4 / 3 ms | 1.14% / 0.23% / 0.08% | 6 / 66 / 666 ms | |
| 256 | 10 ms / 100 ms / 1 s | 12 / 103 / 1002 ms | 1.97% / 0.35% / 0.12% | 6 / 66 / 666 ms | 1.8 KB |
| 1024 | 10 ms / 100 ms / 1 s | 23 / 103 / 1003 ms | 6.96% / 0.84% / 0.20% | 7 / 66 / 667 ms | 1.1 KB |
| 4096 | 10 ms / 100 ms / 1 s | 56 / 106 / 1014 ms | 19.21% / 2.48% / 0.28% | 7 / 68 / 667 ms | 0.9 KB |

The rows for `MaxWatchBytes` and the heads of a WATCH were measured on 2026-11-23 on the same machine, with `TestMeasureWatch/unknown` and `TestMeasureVerifyHeads` (`KOLO_SYNC_MEASURE=1`), with the load average at 12 to 14. A connection that names logs the server does not offer costs the server 685, 584 and 655 bytes a name at 1024, 16,384 and 65,536 names in the first run, and 769, 587, 590 and 486 bytes at 1024, 16,384, 65,536 and 95,869 names in the run that measures the idle processor (the small counts include the fixed cost of the connection): 95,869 names, what `MaxWatchBytes` allows, held about 47 MiB and used 0.14%, 0.61%, 1.71% and 2.24% of a core at 1024, 16,384, 65,536 and 95,869 names with `WatchGap` 100 ms, since a name that is not offered is probed with a map lookup. A log the server offers costs more to probe, as the table above shows, and is bounded by what the application offers. The first heads of all n logs arrive within one `WatchGap` and a few ms.

The per-peer byte budget was measured on 2026-11-23 with `TestMeasurePeerBudget` (`KOLO_SYNC_MEASURE=1`), same machine, without `-race`, while other programs kept the load average at 18 to 19 (the 1 minute figure never fell below 10 in 14 minutes, so the numbers are noisy). A fresh follower pulled a log of 64 MiB (64 entries of 1 MiB) from a server with the budget off (a bucket no pull can empty) and from one at the defaults, alternating, 7 runs each on loopback: median 1084 ms off and 991 ms at the defaults (range 564 to 1270 ms and 679 to 1434 ms), so the budget does not slow a catch-up that fits the bucket by anything the noise shows. Over the 40 ms path, 2 runs each took 13.2 and 13.7 s off and 13.5 and 13.5 s at the defaults, about 5 MiB a second, a sixth of the default rate. A catch-up of 576 MiB on loopback, 320 MiB over the 256 MiB bucket, with a retry one second after each `ErrBusy`, took 10.7 s off and 11.1 s at the defaults with 2 retries: past the bucket a pull proceeds at the rate, 32 MiB a second, so the extra time is about the bytes over the bucket divided by the rate less the time the pull needed anyway, and a smaller bucket or rate makes it longer. Taking and giving back the cost of an answer is 163 to 267 ns, against answers of up to 1 MiB.

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
