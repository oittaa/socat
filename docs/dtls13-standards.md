# DTLS 1.3 standards and code map

Checked 2026-09-07. Read the relevant sections before changing behavior.
[Status and peer limits](dtls13.md).
[BCP 14 requirement matrix vs OpenSSL, wolfSSL, and Pion](dtls13-compliance.md).
[PMTU investigation](dtls13-pmtu.md).

## References

| Reference | Use |
| --- | --- |
| [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.txt) | DTLS 1.3: records/epochs (§4), handshake/cookies/fragmentation (§5), ACKs (§7), KeyUpdate (§8), CID management (§9), application data (§10). |
| [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.txt) | Current TLS 1.3 base. Review §1.2's changes; apply DTLS-specific rules where they differ. |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.txt) | Original TLS base, for older documents' section numbers. Do not reuse those numbers in RFC 9846. |
| [RFC 9146](https://www.rfc-editor.org/rfc/rfc9146.txt) | CID negotiation/ownership (§§3, 6). Its DTLS 1.2 record encoding does not apply. |
| [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.txt) | DPLPMTUD sizes, probe/raise timers, and unfragmented probe requirements. |
| [RFC 9853](https://www.rfc-editor.org/rfc/rfc9853.txt) | RRC (§§3–5), amplification and forwarding (§§8–9). CID negotiation alone does not validate an address. |
| [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.txt) | Informational hybrid framework; does not assign ML-KEM groups. |
| [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.txt) | Hybrid shares/secrets (§4), identifiers and DTLS applicability (§7). X25519 hybrid puts ML-KEM first; NIST hybrids put ECDHE first. |
| [TLS ML-DSA draft-05](https://www.ietf.org/archive/id/draft-ietf-tls-mldsa-05.txt) | Pinned CertificateVerify mapping (§3). Empty ML-DSA context is distinct from the TLS CertificateVerify context string. Rechecked 2026-09-07: still draft-05 (IESG approved, RFC not published). |
| [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.txt) | ML-DSA X.509 encodings; prefer Go's parser. This is not the TLS mapping. |
| [IANA TLS parameters](https://www.iana.org/assignments/tls-parameters/) | Identifiers and DTLS applicability before adding wire mappings. |

Check `/info/rfcNUMBER` and the
[TLS ML-DSA datatracker page](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)
before updating mappings. A Reported erratum is not a verified correction.

## Code map

Unqualified paths are under `internal/dtls13/`.

| Area | Starting points |
| --- | --- |
| Records, nonce/sequence reconstruction, replay, epochs | `record.go`, `protection.go`, `session.go` |
| Transcripts, cookies, certificates, signatures | `handshake_client.go`, `handshake_server.go`, `certificate.go`, `signature.go` |
| Stateless cookie verification and bounded admission | `cookie.go`, `admission.go`, `listener.go` |
| Fragmentation, ACKs, retransmissions, KeyUpdate | `fragment.go`, `flight.go`, `ack.go`, `post_handshake.go` |
| CID pools, routing, migration, peer filters | `connection_id.go`, `listener.go`, `path.go` |
| PMTU sizes, handshake shrink, padded RRC probes | `pmtu.go`, `pmtu_probe.go`, `pmtu_df_linux.go` |
| Algorithms and Go-default alignment | `groups.go`, `offer.go`, `algorithms_test.go` |
| Receive timeouts, queues, cancellation | `conn.go`, `session.go`, `internal/xio/dtlsopen/config.go` |
| Endpoint adaptation and per-direction capabilities | `internal/xio/dtlsopen/stream.go`, `internal/relay/semantics.go` |

## Endpoint packetization

`dtls13.Conn` is a datagram API: oversized writes fail and short reads
truncate. RFC 9147 allows multiple records per datagram; it does not define
our `Write` API. `dtlsopen.wrap` starts strict. Stream directions may split
writes using the current `MaxDatagramSize()` (peer CID length can change
overhead) and retain up to 16 KiB of record tails. Message and unknown peers,
including DTLS-to-DTLS, stay strict. The relay loop has no DTLS record logic.
Preserve cancellation; do not let zero-copy bypass the adapter. Ordinary EXEC
works; `EXEC,nofork` rejects DTLS.

Classic documentation asks users to size DTLS transfers with `-b`. OpenSSL's
write path does not split application writes into MTU-sized records. Automatic
stream packetization is our endpoint policy; see the README.

## Cookies, timeouts, writes

RFC 9147 §5.1 / RFC 9846 §4.3.2: the cookie authenticates address, timestamp,
selected parameters and the first ClientHello hash with a listener HMAC key,
expires after 60 seconds, and is the only server-handshake constructor.
Invalid cookies get `illegal_parameter`. An evictable plaintext cache covers
fragmented hellos and retry retransmissions; verification does not need the
original entry.

Handshake read keys retire after the client's final flight is acknowledged.
The server keeps them for four minutes (RFC 9147 §5.8.1: twice the default MSL)
or until a peer KeyUpdate, including while idle.

`so-rcvtimeo` / `rcvtimeo` map to `HandshakeReadTimeout` per association.
Zero disables it. Do not set the shared listener UDP deadline. Fragments, ACKs
and duplicate records refresh the wait; outgoing retransmits and wrong-peer
traffic do not. At expiry, drain the queued snapshot; new ignored traffic
cannot prolong it. `ErrHandshakeReadTimeout` is not stream-`Retryable`.
Post-handshake receive timeouts remain retryable; `-T` bounds idle transfer.

Application writes use the caller's deadline (zero means none). The shared UDP
writer bounds each socket attempt to one second and retries only an attempt
known to have sent zero bytes, with a fresh record number. The connection
event loop owns sequence numbers, keys and CID state. Client sockets send
from that loop; listeners keep a shared writer.

KeyUpdate waits for ACKs of the update and preceding post-handshake messages;
later messages wait for the new sending epoch. That follows
[erratum 8047](https://www.rfc-editor.org/errata/eid8047), **Reported** rather
than verified at the review date. Check its status before treating the
ordering as normative. CID tests live in `connection_id*_test.go`.
