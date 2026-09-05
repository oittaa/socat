# DTLS 1.3 standards and code map

References checked on 2026-09-05. Read the relevant sections before changing
behavior. [Status and peer limits](dtls13.md) ·
[Remaining work](dtls13-follow-up.txt). This guide is not a completed audit.

## References

| Reference | Use |
| --- | --- |
| [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.txt) | DTLS 1.3: records/epochs (§4), handshake/cookies/fragmentation (§5), ACKs (§7), KeyUpdate (§8), CID management (§9), application data (§10). |
| [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.txt) | Current TLS 1.3 base. Review §1.2's changes before merge; apply DTLS-specific rules where they differ. |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.txt) | Original TLS base, needed for older documents' section references. Do not reuse its section numbers in RFC 9846. |
| [RFC 9146](https://www.rfc-editor.org/rfc/rfc9146.txt) | CID negotiation/ownership context (§§3, 6). Its DTLS 1.2 record encoding does not apply here. |
| [RFC 9853](https://www.rfc-editor.org/rfc/rfc9853.txt) | RRC negotiation and basic/enhanced validation (§§3–5), amplification and forwarding attacks (§§8–9). CID negotiation alone does not validate an address. |
| [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.txt) | Informational hybrid construction and security framework (§§3, 6); does not assign concrete ML-KEM groups. |
| [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.txt) | Hybrid shares/secrets (§4), identifiers and DTLS applicability (§7). X25519 hybrid puts ML-KEM first; NIST hybrids put ECDHE first. |
| [TLS ML-DSA draft-05](https://www.ietf.org/archive/id/draft-ietf-tls-mldsa-05.txt) | Pinned CertificateVerify mapping (§3), still a draft. Empty ML-DSA context is distinct from the TLS CertificateVerify context string. |
| [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.txt) | ML-DSA X.509 encodings; prefer Go's parsing and verification. This does not standardize the separate TLS mapping. |
| [IANA TLS parameters](https://www.iana.org/assignments/tls-parameters/) | Verify identifiers and DTLS applicability before adding wire mappings. |

Check RFC status/verified errata via each `/info/rfcNUMBER` page and the
[current TLS ML-DSA status](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)
before updating mappings. Record the section and erratum when relevant;
a Reported erratum is not a verified correction.

## Code map

Unqualified paths below are under `internal/dtls13/`.

| Area | Starting points |
| --- | --- |
| Records, nonce/sequence reconstruction, replay, epochs | `record.go`, `protection.go`, `session.go` |
| Transcripts, cookies, certificates, signatures | `handshake_client.go`, `handshake_server.go`, `certificate.go`, `signature.go` |
| Fragmentation, ACKs, retransmissions, KeyUpdate | `fragment.go`, `flight.go`, `ack.go`, `post_handshake.go` |
| CID pools, routing, migration, peer filters | `connection_id.go`, `listener.go`, `path.go` |
| Algorithms and Go-default alignment | `groups.go`, `offer.go`, `algorithms_test.go` |
| Receive timeouts, queues, cancellation | `conn.go`, `session.go`, `internal/xio/dtlsopen/config.go` |
| Endpoint adaptation and per-direction capabilities | `internal/xio/dtlsopen/stream.go`, `internal/relay/semantics.go` |

## Endpoint packetization contract

- `dtls13.Conn` remains a datagram API: oversized writes fail and short
  reads truncate. RFC 9147 permits multiple records per datagram; it does
  not define our Go `Write` API or guarantee application delivery.
- The adapter in `dtlsopen.wrap` starts strict. Endpoint pairing selects
  splitting/buffering independently for each direction, following wrappers
  and dual-address halves. Message and unknown peers, including DTLS-to-DTLS,
  stay strict. The relay loop has no DTLS record logic.
- Stream writes use the current `MaxDatagramSize()` between chunks because
  replacement peer CIDs can change overhead. Retry a pre-send
  `ErrDatagramTooLarge` only if capacity shrank. Serialize writes, preserve
  partial counts and never resend completed chunks.
- Stream reads retain up to 16 KiB of record data, returning remainders
  before another underlying read. Zero-length reads consume nothing.
  `MaxDatagramSize()` is an outgoing limit, not the receive-buffer size.
- Preserve cancellation and prevent zero-copy traversal from bypassing the
  adapter. Forked RECVFROM transfers directly when adapted, preserving the
  original boundaries. Ordinary EXEC works; `EXEC,nofork` rejects DTLS.

The official [socat documentation](https://repo.or.cz/socat.git/blob/12c08bf66d709fba17035ce95d85bd218428d9ba:/doc/socat.yo)
asks users to size DTLS transfers with `-b`; its default block is 8192 bytes.
Release and reviewed master in [classic-baseline.json](../scripts/classic-baseline.json)
have identical DTLS documentation, tests and `xio-openssl.c` (checked 2026-09-05).
The pinned OpenSSL [write path](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/rec_layer_d1.c)
does not split application writes into MTU-sized records; its read path
retains tails. Automatic stream packetization is our documented endpoint policy.

## Handshake key retention

Handshake read keys are retired after the client's final flight is acknowledged.
The server retains them for four minutes to recover lost final ACKs (RFC 9147
section 5.8.1: twice the default MSL), or until a peer KeyUpdate proves progress.
This absolute retention timer runs even when the connection is idle.

## Handshake receive-timeout contract

- Map `so-rcvtimeo` / `rcvtimeo` to `HandshakeReadTimeout` per association,
  starting at the first wait. Zero disables it. Never set the listener's
  shared UDP read deadline or copy OpenSSL's historical retry count.
- Peer/framing/CID checks precede refresh; authentication/replay checks follow.
  Fragments, ACKs and duplicate records count as reception. A complete
  handshake message is not required. Outgoing retransmits, wakeups, malformed
  framing and wrong-peer/CID traffic do not refresh the wait.
- At expiry, process a snapshot of queued datagrams. New ignored traffic
  cannot prolong the expired wait. Cancellation and the absolute handshake
  deadline take precedence, including during the drain.
- `ErrHandshakeReadTimeout` ends the association without a stream `Retryable`
  marker. Explicit connect retry may start a new attempt. Listener cleanup
  releases only that association. Post-handshake receive timeouts remain
  retryable; `-T` supplies the idle-transfer bound.

## Write-deadline contract

Application writes follow the caller's current deadline; zero means no deadline.
The shared UDP writer bounds each socket attempt to one second. Only an attempt
known to have sent zero bytes may retry, using a fresh record number. Cancellation
interrupts the active attempt before the writer moves to another association.
Control writes retain their separate one-second bound.

## CID review

Local RFC 9147 section 9 review completed on 2026-09-05. The checklist below
distinguishes protocol requirements from local policy. Tests are under
`internal/dtls13/`; wire cases hand-author CID payloads and handshake headers.
This closes the local CID coverage item, not the independent whole-stack
security review or spare-CID interoperability work.

| Contract | Implementation | Tests |
| --- | --- | --- |
| Negotiation/direction restrictions (MUST) | `handshake.finish`, `requestCIDs`, `receivePost` | `TestCIDNegotiatedDirections`, `TestCIDEmptyRotationCanBeReplaced` |
| Vector lengths, usage and malformed input | `parseCIDs`, `encodeCIDs` | `TestCIDRFCWire`, `TestCIDAuthenticatedWireErrors`, `TestCIDAuthenticatedPoolBounds` |
| Immediate CID on every subsequent record (MUST) | `receiveCIDs`, `sendRecordWith` | `TestCIDEmptyRotationCanBeReplaced`, existing CID/RRC rotation tests |
| One outstanding update/unfulfilled request (MUST); ACK is not fulfillment | `startPost`, `requestCIDs`, `receiveCIDs` | `TestCIDOverlappingRequestsAndIssuance`, existing ACK-only/empty/immediate-response tests |
| Prompt spare replies and ordered use (SHOULD); fewer/empty replies (MAY) | `advancePost`, `provideCIDs`, `useSpareCID` | `TestCIDRequestCountsAndExhaustion` |
| ACK/retransmission rules (sections 5, 7); conservative KeyUpdate ordering below | `receiveHandshake`, `acknowledgePost`, `advancePost` | `TestCIDLossReorderAndConcurrentKeyUpdate` |
| New-path CID use (SHOULD), RFC 9853 path validation | `path.go` | `TestCIDRepeatedMigrationAndProbeExpiry`, existing in-flight rotation tests |
| Bounded pools, fragments and authenticated retirement (local policy) | `provideCIDs`, `reassembler`, `usedLocalCID`, `Listener` | `TestCIDFragmentResourceBounds`, `TestCIDListenerAuthenticationRetirementAndCleanup` |

The review fixed one defect: a later zero-length CID must not erase the
handshake's permission to receive replacement CIDs. Requests remain forbidden
while sending an empty CID. Pool renewal and independent peer limits remain
in the [status document](dtls13.md).

Current KeyUpdate ordering waits for ACKs of the update and preceding
post-handshake messages; later messages wait for the new sending epoch.
This follows the proposal in [erratum 8047](https://www.rfc-editor.org/errata/eid8047),
which was **Reported**, not verified, at the review date. Check its status
before treating that ordering as a normative requirement.
