# Protocol

The wire format of kolo-sync and the standards it follows. How the calls use it is in [guide.md](guide.md); bounds are in [limits.md](limits.md).

## Formats

One bidirectional stream per `Pull`, `PullCiphertext`, `FetchHeader`,
`FetchHead`, `Fetch`, `FetchWithKeys` or `FetchKeys` call, opened by the
client (the puller below).
Every message is
a length prefix and a [kolo-codec](https://github.com/ciranda-dev/kolo-codec)
payload:

    uint32(length, little-endian, 1 to 4194304) ‖ uvarint(version 1) ‖ uvarint(type) ‖ fields

    1 HEAD_REQ     owner public key (32) ‖ log ID (32)
    2 PROOF_REQ    uvarint(first) ‖ uvarint(second)
    3 ENTRIES_REQ  uvarint(start) ‖ uvarint(end) ‖ bool(keys)
    4 STATE_REQ    uvarint(start) ‖ uvarint(end) ‖ bool(keys)
    5 HEAD         bytes(head) ‖ bytes(log header)
    6 PROOF        bytes(consistency proof)
    7 ENTRIES      uvarint(n) ‖ n × (bytes(record) ‖ bytes(ciphertext) ‖ bytes(marker) ‖ bytes(key))
    8 STATE        uvarint(next) ‖ uvarint(n) ‖ n × (uvarint(index) ‖ uvarint(0 marker, 1 key) ‖ bytes(marker or key))
    9 ERROR        uvarint(code: 1 not found, 2 busy, 3 too large, 4 protocol)
    10 FETCH_REQ   uvarint(start) ‖ uvarint(end) ‖ uvarint(size)
    11 FETCH       uvarint(n) ‖ n × (bytes(record) ‖ bytes(ciphertext) ‖ bytes(marker) ‖ bytes(key) ‖ bytes(inclusion proof))
    12 STREAM_REQ  uvarint(start) ‖ uvarint(size) ‖ bool(keys) ‖ uvarint(credit)
    13 CREDIT_REQ  uvarint(credit)

`bytes(x)` is a uvarint length and `x`. Heads, headers, records, markers
and proofs are kolo-log's binary encodings, at most 4 KiB each; a record
or non-empty marker is at least 128 bytes, a key 0 or 32 bytes. A server accepts
only types 1 to 4, 10, 12 and 13, and a puller only types 5 to 9 and 11, checked
before the fields. The stream starts with HEAD_REQ, answered by HEAD or
ERROR. Each later request gets one answer: PROOF_REQ needs first ≤ second
≤ the head's size; ENTRIES_REQ and STATE_REQ need start ≤ end < the head's
size, `end` included; FETCH_REQ needs start ≤ end < size ≤ the head's
size, and FETCH gives each entry from `start` on with its inclusion proof
in the tree of `size` entries. ENTRIES, FETCH and STATE may stop early to
fit in one message (ENTRIES and FETCH carry at least one entry, STATE
covers at least one index); STATE's `next` is the
first index it did not cover, and its items
are in index order. Keys come only when the request sets `keys` and the
peer has `Keys` access, or, in FETCH, whenever the peer has `Keys`
access; a key in an answer to a request without `keys` is
a protocol error. `FetchWithKeys` sends the same bytes as `Fetch` whatever
keys the client holds; it opens the held entries after the stream ends,
so only the time before the client's next request depends on them. `PullWith` sends the messages `Pull`
sends: with `NoMarkers` it sends no STATE_REQ for markers alone and, when
an ENTRIES answer holds a deleted entry, one PROOF_REQ for the entries
before it; a pull that ends with `ErrMarked` or `ErrBehind` sends no
STATE_REQ; with `KeysFrom` its STATE_REQ for keys starts at that index or
later. A puller may send a request before the answer to the one
before it is complete, and may keep several waiting: the server reads them in
order and sends one answer for each, in the same order, so the puller reads
each answer as the one its oldest unanswered request asked for. A server
that does not know STREAM_REQ is pulled from this way: `Pull` sends the next
ENTRIES_REQ, starting at the end of the answer being read, and the PROOF_REQ for that end, as soon as
the count at the start of the ENTRIES answer is read, at most
`PullOptions.InFlight` ENTRIES_REQs ahead (3 if it is 0). That
is one answer for each round trip: the next request cannot go out before the
count of the answer before it is known. STREAM_REQ, below, does not have that limit.
An ERROR, another version, non-minimal varints or
trailing bytes end the stream. There is no JSON form.

## Streamed entries

STREAM_REQ asks for the entries from `start` up to `size`, the size of the head the
puller is filling to, and says how many bytes of answers the server may send before it
needs more: `credit`. The server then sends, without waiting for another request, each
ENTRIES answer from `start` on, built as for ENTRIES_REQ, followed by one PROOF, the
consistency proof from the end of that answer to `size`, unless the answer ends at `size`.
The entries of the answers are consecutive, so the puller learns where each starts and
ends from the count of the one before. It needs no request to know that, which is why the
link stays full.

    STREAM_REQ(start, size, keys, credit)
      ENTRIES(start .. a)   PROOF(a, size)
      ENTRIES(a .. b)       PROOF(b, size)
      ...
      ENTRIES(y .. size)                      no PROOF: it ends at size

Credit is flow control. Each ENTRIES answer costs its message length, the 4-byte length prefix
excluded; the PROOF costs nothing. The server sends an answer only while its credit is above 0,
and the answer that takes it to 0 or below is sent whole, so the credit may end below 0, and
the next credit pays that debt first. When the credit is used up the server reads the next
request. CREDIT_REQ adds its `credit` to the credit of the stream; a puller sends it before it
needs it, and the server reads it as soon as it is done with the answers the credit paid for,
so a puller that keeps enough credit ahead (at least the bandwidth-delay product) never makes the
server wait. The server holds no more than one answer in memory at a time, and the puller
decides how much credit is waiting, so the memory a puller spends on answers it has not stored is
its own 6 MiB bound and not the server's.

A server accepts these requests only after HEAD, one STREAM_REQ at a time:

- STREAM_REQ needs `start` < `size` ≤ the head's size, and `credit` from 1 to 67108864 (64 MiB);
  it replaces the credit and the position of any earlier STREAM_REQ on the stream, which are used
  up by then, since the server reads requests in order.
- CREDIT_REQ needs a STREAM_REQ before it, and `credit` from 1 to 67108864. The credit of the stream is
  capped at 64 MiB. When `size` is reached it adds credit to nothing and has no answer; the next answer on the stream is
  the answer to the next request.
- The log is looked up and authorized again before each answer, so a withdrawn log or a peer that lost
  access gets ERROR 1 in place of the next answer, which ends the stream. `keys` and `Keys` access
  decide the keys as for ENTRIES_REQ.
- Any other request is answered as for a stream with no STREAM_REQ, once the credit is used up. A value that is not valid is
  ERROR 4, which ends the stream, as for any other request.

A puller that has sent STREAM_REQ and CREDIT_REQs reads exactly the answers they pay for. It counts
the credit as the server does, from the length of each ENTRIES message, so it knows when the server
is done and the stream is free for other requests, such as STATE_REQ, without a marker in the answers. An answer
that does not start where the one before ended, holds no entry or more than asked, a PROOF where there should be
ENTRIES or the other way round, a missing PROOF, a PROOF after the answer that ends at `size`, an ERROR, or
a message that is too large, malformed or late, is an error of the pull, as it is for ENTRIES_REQ.
A puller that must stop early, such as one that finds a delete marker with `NoMarkers`, sends no more credit and
reads and drops what the server still owes, which is at most the credit it granted and one answer, before it
uses the stream for other requests.

### Negotiation and fallback

There is no negotiation message. A puller sends STREAM_REQ as its first request for entries,
and learns from the answer:

- A server that knows STREAM_REQ streams.
- A server that does not know it answers ERROR 4, as it does to any type it does not know, and ends the stream. The
  puller then opens a new stream, sends HEAD_REQ again, and pulls as in the first section, with
  ENTRIES_REQ and PROOF_REQ, from the index it had. It costs the one round trip of the refusal and the one of
  the new HEAD_REQ, once for each pull that has entries to get. ERROR 4 to any later request is an error of the pull, not a
  fallback, since the server has shown that it streams.
- A server does not stream unless it is asked, so a puller that never sends STREAM_REQ is served with
  the requests of types 1 to 4 and 10.

A refusal that is only ERROR 4 cannot tell a server that does not know STREAM_REQ from one that has found it
invalid; a puller sends only valid ones, so for it, the same fallback is harmless.

## References

- [RFC 9162, Certificate Transparency Version 2.0](https://www.rfc-editor.org/info/rfc9162) (Experimental, December 2021).
  Takes: signed tree heads (4.10), consistency proofs (2.1.4), get-sth (5.2), get-sth-consistency (5.3),
  get-entries (5.6) and the monitor that keeps a whole log (8.2). `Fetch` follows inclusion proofs (2.1.3) and
  get-proof-by-hash (5.4), whose proof is in the tree of a size the client names, and checks them as 8.1.5 says,
  against a head the client trusts.
  Not implemented: HTTPS and JSON (kolo-codec messages on a kolo-secure stream instead); get-proof-by-hash as a
  request, since a replica holds every entry and rebuilds the root.
  Differs: HEAD also carries the signed log header, which a new replica needs; each chunk comes with the proof from
  its end to the head; heads have no timestamp, so a newer head is a larger one; any peer with a verified copy can
  serve, since trust comes from the owner's signatures only; and the STATE request, which the standard has no need
  for, carries kolo-log's delete markers and per-entry keys.
  `Fetch` differs in asking by index, as get-entry-and-proof did in RFC 6962 (4.8), since the client knows where an
  entry is but not its leaf hash; in asking for a range, as get-entries (5.6) does, with one proof per entry and an
  answer that may stop early; and in sending the peer's head once at the start of the stream instead of in every answer.
- [RFC 6962, Certificate Transparency](https://www.rfc-editor.org/info/rfc6962) (Experimental, June 2013, obsoleted by RFC 9162).
  Takes: get-entry-and-proof (4.8), an entry and its inclusion proof by index and tree size, which RFC 9162 replaced
  with get-proof-by-hash.
- [RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032) (Informational, January 2017).
  Takes: Ed25519ctx (5.1, 8.3) through kolo-log's contexts.
  Not implemented: kolo-sync signs nothing.
- [RFC 9113, HTTP/2](https://www.rfc-editor.org/info/rfc9113) (Proposed Standard, June 2022).
  Takes: the stream concurrency limit and refused streams (5.1.2, 6.5.2). Kolo serves 16 streams per connection,
  below the 100 recommended there, to bound memory with 4 MiB messages.
  Not implemented: HTTP/2 itself.

The limit of 4 MiB for a message is a common default for the largest received message, and the 60 s for each message is
a common server default. Kolo times each whole message, so a peer cannot hold a stream by sending one byte at a time.
