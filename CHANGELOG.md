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
- `ServerOptions.MaxWatched` (default 1024, at least 55): the most distinct logs a connection may watch, ERROR 3 past it.
  One watch stream per connection; watch streams are counted apart from `MaxTotalStreams`, so idle watchers do not take the
  slots that serve pulls. A server of v0.1.0 answers WATCH_REQ with ERROR 4.
- `PullStats.Received`: the bytes of ENTRIES answers read so far, also of the answer being read, for progress that
  moves with the bytes instead of once per answer.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-sync.
