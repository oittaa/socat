# DTLS 1.3 standards and bug-fixing guide

Reference status checked on 2026-09-05. Read the applicable sections before
changing protocol behavior. This guide records sources and review targets;
it is not a completed conformance audit. Implementation scope, exact peer
revisions, and completed tests are in [dtls13.md](dtls13.md). Remaining work
is in [dtls13-follow-up.txt](dtls13-follow-up.txt).

## Core references

| Reference | Purpose and relevant sections |
| --- | --- |
| [RFC 9147: DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147.txt) | Primary DTLS specification. Sections 4-5: records, epochs, PMTU, cookies, fragmentation and flights; 7-9: ACKs, key updates and CID updates; 10: application data. |
| [RFC 9846: TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846.txt) | Current TLS base specification, replacing RFC 8446 in July 2026. Read section 1.2's changes, section 4's handshake/authentication, and sections 5-7's protection, alerts and key schedule. Apply the DTLS-specific rules where they differ. |
| [RFC 8446: original TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.txt) | Retain for the section references used by RFC 9147 and the pinned ML-DSA draft. Section numbers differ from RFC 9846; do not silently substitute the same section number in the newer document. |
| [RFC 9146: Connection Identifier for DTLS 1.2](https://www.rfc-editor.org/rfc/rfc9146.txt) | CID negotiation, ownership, length and address-update context referenced by DTLS 1.3; especially sections 3 and 6. Its DTLS 1.2 record encoding does not replace RFC 9147's record format. Reading it does not add DTLS 1.2 support to our scope. |
| [RFC 9853: Return Routability Check](https://www.rfc-editor.org/rfc/rfc9853.txt) | Updates RFCs 9146/9147. Sections 3-5 define negotiation, messages and basic/enhanced path validation; sections 8-9 address amplification, forwarding attacks and privacy. A negotiated CID alone does not establish negotiated RRC or a validated new address. |

RFC 9846 retains the TLS 1.3 version while tightening and clarifying rules.
Its section 1.2 needs an explicit review against this implementation, including
key-share reuse, key-update limits, tickets, alerts and extension bounds.
Adding this reference does not claim that review is complete. Use the
DTLS-specific epoch, ACK and record rules when assessing TLS changes.

## Algorithm references

These apply to algorithm and authentication work; agents fixing endpoint
buffering do not need to read every cryptographic specification first.

| Reference | Purpose and relevant sections |
| --- | --- |
| [RFC 9954: Hybrid Key Exchange in TLS 1.3](https://www.rfc-editor.org/rfc/rfc9954.txt) | Informational construction and security framework, referenced normatively by RFC 10024. Sections 3 and 6 cover negotiation, concatenation and security assumptions. It does not assign our concrete ML-KEM groups. |
| [RFC 10024: PQ/T Hybrid Key Agreement Mechanisms](https://www.rfc-editor.org/rfc/rfc10024.txt) | Concrete X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 encodings. Section 4 defines shares, validation and secrets; section 7 assigns identifiers and DTLS applicability. The X25519 hybrid places ML-KEM first; the NIST-curve hybrids place ECDHE first. Do not infer component order from the group name. |
| [draft-ietf-tls-mldsa-05](https://www.ietf.org/archive/id/draft-ietf-tls-mldsa-05.txt) | Pinned TLS ML-DSA mapping, still a draft. Section 3 covers schemes, certificates and CertificateVerify. The ML-DSA context parameter is empty; it is distinct from the TLS CertificateVerify context string. Check the [current document status](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/) before updating the mapping. |
| [RFC 9881: ML-DSA in X.509](https://www.rfc-editor.org/rfc/rfc9881.txt) | Certificate, public-key, private-key and signature identifiers/encodings. This published certificate standard does not make the separate TLS signature mapping a published RFC. Prefer Go's parsing and verification. |
| [IANA TLS parameters](https://www.iana.org/assignments/tls-parameters/) | Check the relevant group's, signature scheme's or cipher suite's assigned value, reference and DTLS applicability before adding a wire mapping. An assigned value alone is not an implementation. |

Keep the user's algorithm policy: prefer native Go primitives and X.509
verification; `golang.org/x/` imports are allowed. Do not add local security
allowlists without a protocol requirement. Go-default drift tests signal work
to integrate a new wire mapping; they cannot enable it automatically. Optional
PSKs, resumption, early data and post-handshake client authentication remain
outside the current implementation scope.

## Find the relevant code

Paths start at the repository root; unqualified filenames share the preceding
file's directory.

| Bug area | Starting points | Reading |
| --- | --- | --- |
| Datagram sizing, truncation and endpoint adaptation | `internal/xio/dtlsopen/open.go`, `internal/dtls13/conn.go`, `internal/relay/relay.go` | RFC 9147 sections 4.3-4.4 and 10; official socat/OpenSSL evidence below. |
| Record protection, replay and epochs | `internal/dtls13/record.go`, `protection.go`, `session.go` | RFC 9147 section 4; RFC 9846 sections 5 and 7. |
| Transcript, cookies and authentication | `internal/dtls13/handshake_client.go`, `handshake_server.go`, `certificate.go`, `signature.go` | RFC 9147 section 5; RFC 9846 section 4; algorithm references as applicable. |
| Loss recovery and key updates | `internal/dtls13/fragment.go`, `flight.go`, `ack.go`, `post_handshake.go` | RFC 9147 sections 5.5, 5.8 and 7-8; RFC 9846 sections 4.7.3 and 5.5. |
| CID pools, routing and migration | `internal/dtls13/connection_id.go`, `listener.go`, `path.go` | RFC 9146 sections 3 and 6; RFC 9147 section 9; RFC 9853 sections 3-5 and 8-9. |
| Hybrid key exchange | `internal/dtls13/groups.go`, `offer.go`, `algorithms_test.go` | RFC 9954 sections 3 and 6; RFC 10024 sections 4, 6 and 7. |

## Endpoint packetization review

The proposed stream adapter belongs near `dtlsopen.wrap`, before
`xio.WrapStream`, if stream semantics are selected. Keep the existing datagram
contract of `dtls13.Conn`: oversize application writes fail and short reads
truncate. This API choice is ours: RFC 9147 section 4.3 permits multiple
records in a datagram and does not define a Go `Write` API. A stream adapter
also does not add reliable or ordered application delivery.

Do not install unconditional write splitting as a claimed compatibility fix.
The current `wrap` callback sees only its own endpoint and cannot distinguish
an 8192-byte file chunk from an 8192-byte UDP message. Splitting the latter
changes application framing. First specify how endpoint pairing selects
stream adaptation while preserving datagram sources. Keep DTLS packetization
in the endpoint layer; any selection plumbing must not teach the generic
relay DTLS record details. Follow AGENTS.md for compatibility decisions.

Source evidence checked at the pinned revisions:

- Official socat release `12c08bf66d709fba17035ce95d85bd218428d9ba` and master
  `af5388c898c7bb60997935aee93c223deba60c4a` have identical `doc/socat.yo` and
  `xio-openssl.c`. The [DTLS endpoint documentation](https://repo.or.cz/socat.git/blob/12c08bf66d709fba17035ce95d85bd218428d9ba:/doc/socat.yo)
  tells users to size datagrams with `-b`; the default transfer block is 8192.
  The endpoint forwards each block to `SSL_write` and reads with `SSL_read`.
- OpenSSL `82733d90b5bc58b8d064ed49c282aa028664a1ed` checks a 16 KiB application
  write limit in [ssl/d1_msg.c](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/d1_msg.c).
  [ssl/record/rec_layer_d1.c](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/rec_layer_d1.c)
  sends one record template, rather than splitting application writes into
  MTU-sized records. Its short-read path retains the remaining record bytes
  through `ssl_release_record` in `ssl/record/rec_layer_s3.c`.

For the selected stream path, preserve unread bytes in a bounded receive
buffer large enough for the supported incoming application record limit.
`MaxDatagramSize()` is an outgoing limit, not a receive-buffer size. Return
buffered bytes before another underlying read; a zero-length read must not
consume a record. Do not coalesce separate application records unnecessarily.

Do not cache the outgoing limit at handshake completion. Our generated CIDs
have a fixed length, but peer-provided replacement CIDs can change outgoing
overhead. `Conn.publish` recomputes the limit from the active peer CID.
Account for changes between chunks, report partial progress accurately,
serialize each multi-record stream write, and preserve cancellation,
deadlines and half-close through the wrapper.

Tests must cover default-block file transfer in both directions, short reads
and peer/local MTU asymmetry, unchanged fitting datagrams, explicit oversized
UDP behavior, direct-Conn rejection, and interrupted writes without duplicated
bytes. Rerun the five unmodified official DTLS scorecard names after a fix;
record actual results instead of assuming all failures share this cause.
`RCVTIMEO_DTLS` remains a separate socket-timeout investigation.

## Spare-CID assurance and reference limitations

Independent spare-CID issuance/replenishment interoperability is a follow-up
when a suitable upstream adds support; its current absence is not a merge
blocker. The pinned OpenSSL has no DTLS 1.3 CIDs, Pion rejects the management
messages, and wolfSSL acknowledges requests without issuing spares. Exact
revisions, evidence and the narrower passing checks are in
[dtls13.md](dtls13.md). Do not generalize these results to future releases.

Before merge, review the implementation against RFC 9147 section 9 and the
related ACK, key-update and RFC 9853 rules. Check existing tests for gaps in
request/response state, bounded pools, spare consumption and repeated
replenishment, immediate rotation and retirement, empty/no responses,
malformed input, loss/reordering/duplication and simultaneous key updates.
Include RFC-derived wire cases that do not depend on our own encoder.
Fix any defects found; local tests are not independent interoperability.
Item 2 of [the follow-up plan](dtls13-follow-up.txt) separates this pre-merge
work from future upstream testing.

## Evidence and errata

Use each RFC's `/info/rfcNUMBER` page to check updates and errata; for example,
[RFC 9147 status](https://www.rfc-editor.org/info/rfc9147). Record the section,
erratum identifier and disposition when a fix depends on an erratum. A
Reported erratum is not a verified correction. The existing key-update
ordering decision cites [erratum 8047](https://www.rfc-editor.org/errata/eid8047);
recheck its status before treating the proposal as a normative requirement.

Distinguish a mandatory-rule violation, a recommendation with a justified
exception, an optional feature, a local API policy and an implementation bug.
A passing self-test or overlap with one peer does not prove overall RFC
conformance. Preserve the pinned interoperability limits in `dtls13.md`;
require a reproducer and an observable regression for each claimed fix.
