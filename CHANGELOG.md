# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Breaking: `MinRate` is replaced by `MinProgress`. A message read is no longer cut off when its average speed is
  below 16 KiB/s: it may take as long as it needs while each 16 KiB of it arrives within `Timeout` (60 s), and a peer
  that sends less than 16 KiB in a minute is cut off after one `Timeout`. A message written may take `Timeout` plus its
  size at 500 bytes a second (about 36 minutes for 1 MiB) instead of at 16 KiB/s, so a peer that barely reads cannot
  hold an answer's memory for hours. An answer of about 1 MiB over a path slower than about 8.5 KB/s used to be cut off
  and asked for again from its first byte, so a pull on such a path never finished.
- A request announced larger than 4 KiB is refused with `ErrTooLarge` before its body is read, so no buffer is held
  for a request that trickles in. Every request kolo-sync sends is below 100 bytes.

### Added

- WATCH_REQ and WATCH (types 14 and 15): a stream that starts with WATCH_REQ is answered with the heads of the logs it
  names, and then with the head of each that grows, at most once per `ServerOptions.WatchGap` (default 100 ms). A log that
  is missing, not offered or not authorized is never in a WATCH. The server probes each watched log once per gap with a read
  from memory and signs at most one head per log per growth, however often peers name it.
- `ServerOptions.MaxWatched` (default 8192, at least 55): the most distinct logs a connection may watch, ERROR 3 past it. A
  connection that names a log costs the server about 650 bytes, offered or not. One watch stream per connection; watch
  streams are counted apart from `MaxTotalStreams`, so idle watchers do not take the slots that serve pulls. A server of
  v0.1.0 answers WATCH_REQ with ERROR 4.
- `Follower` (`NewFollower`, `Add`, `Remove`, `Follow`, `Hint`, `Status`, `Next`, `Close`): keeps replicas up to date from every connection
  given to `Follow`, with no limit on the number of logs followed. It names the followed logs in a WATCH_REQ, pulls a log when
  a verified head is larger than the replica, checks a head no larger than the replica locally so that a second history is
  `ErrDiverged`, pulls a log from one peer at a time and not from a peer in backoff, and retries a failed pull per peer and log with
  exponential backoff and jitter (`RetryMin` 1 s, `RetryMax` 10 min). It runs at most `MaxPulls` (32) pulls at once, and
  `MaxPullsPerConn` (15) on one connection; both defaults come from the measurements in docs/limits.md. A peer that answers WATCH_REQ with ERROR 4 is pulled once and
  asked for heads every `Poll` if that is set (0 by default). It keeps no state on disk and forwards no head.
- `examples/follow`: a follower of a log that restarts from its Pebble directory, on 127.0.0.1; docs/guide.md has a
  section on following logs and docs/limits.md the bounds with the numbers they come from.
- `ServerOptions.WatchGap`, `FollowOptions.RetryMin` and `RetryMax` have no upper bound: only a floor (10 ms, 100 ms) that protects the processor and the peers.
- `PullStats.Received`: the bytes of ENTRIES answers read so far, also of the answer being read, for progress that
  moves with the bytes instead of once per answer.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-sync.
