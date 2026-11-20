// Package kolosync replicates kolo-log logs between two peers, pull only, over any
// authenticated Conn: a kolo-secure connection or a kolo-swarm link, direct or relayed.
//
// A Server offers logs, and authorizes each peer per log. Pull opens one stream per log, verifies the
// peer's signed head, fetches the missing range with consistency proofs, and grows a kolo-store Replica,
// which verifies every entry before it stores it. Delete markers and, for authorized peers, entry keys
// follow. Fetch gets a range of entries without a replica, each checked with its inclusion proof against a
// head the client trusts; FetchWithKeys opens them with keys the client holds, which FetchKeys gets from a
// peer with Keys access, so a client can read from a peer that holds ciphertext only. Many logs share one
// connection.
//
// Experimental: the API may change before v1.0.0.
package kolosync
