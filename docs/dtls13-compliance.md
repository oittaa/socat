# DTLS 1.3 requirement matrix

Extracted 2026-09-07 from the documents listed in
[dtls13-standards.md](dtls13-standards.md). This is a source-code audit of
BCP 14 language that actually constrains protocol behavior. It is not a
completed security review.

Peer limits and interop that already ran are in [dtls13.md](dtls13.md).

## Method

- Pulled every `MUST` / `MUST NOT` / `SHALL` / `SHOULD` / `SHOULD NOT` /
  `REQUIRED` / `RECOMMENDED` / `NOT RECOMMENDED` paragraph from RFC 9147,
  RFC 9146 (DTLS 1.3-applicable CID rules), RFC 9853, RFC 10024, and
  [draft-ietf-tls-mldsa-05](https://www.ietf.org/archive/id/draft-ietf-tls-mldsa-05.txt).
- Dropped IANA process text, copyright, BCP 14 boilerplate, DCCP/SCTP-only
  PMTU rules, and RFC 9146's DTLS 1.2 `tls12_cid` record encoding (DTLS 1.3
  uses the unified header in RFC 9147).
- RFC 9846 is the TLS 1.3 base. The full TLS 1.3 MUST set is not restated
  here; §1.2's technical deltas and the features we deliberately omit are.
- RFC 9954 is informational and assigns no groups. RFC 9881 is X.509
  encoding; we use Go's parser.
- Implementations were read at the pins in
  [dtls13-baseline.json](../scripts/dtls13-baseline.json). Runtime tests
  were not re-run for this matrix; existing `dtlsinterop` coverage is noted
  under [Interop](#interop-what-we-can-actually-test).

| Stack | Pin |
| --- | --- |
| Ours | this tree (`internal/dtls13`) |
| OpenSSL | `82733d9` (4.1 development snapshot) |
| wolfSSL | `d72f6d9` |
| Pion | `59f4c33` |

| Mark | Meaning |
| --- | --- |
| yes | Implemented as specified |
| partial | Incomplete, send/receive asymmetric, or a permitted subset |
| no | Missing or contrary |
| n/a | Does not apply yet (feature not implemented, or non-UDP transport) |

Cells are about the **library**, not `s_client` / wolfSSL `examples/server`.
App-level traps that break interop are called out in [Interop](#interop-what-we-can-actually-test).

---

## RFC 9147 — record layer

| Req | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§4** Plaintext seq MUST NOT exceed 2^48−1 | yes | yes | yes | yes (48-bit cap) |
| **§4** `legacy_record_version` MUST be {254,253} (initial CH MAY be {254,255}); MUST be ignored | yes | yes | yes | yes |
| **§4** MAY mix 8- and 16-bit sequence numbers | partial: rx both, tx 16-bit only | partial: rx both, tx 16-bit only | partial: rx both, tx 16-bit only | partial: rx both, tx 16-bit only |
| **§4** Omit length MUST only be last record in datagram; MAY mix with/without length | yes rx; tx always sends length | yes rx; tx always sends length | yes rx; tx always sends length | yes rx; tx always sends length |
| **§4** If CID negotiated, it MUST be in all datagrams | partial: tx always; rx requires CID somewhere in the datagram | n/a (no CID) | yes when CID compiled | yes after handshake CID |
| **§4** MUST NOT mix associations in one datagram; later mismatched CID MUST discard rest | yes | n/a | yes | yes |
| **§4.1** First byte 21/22/26 MUST be DTLSPlaintext | yes | yes | yes | yes |
| **§4.1** Leading bits 001 MUST be DTLSCiphertext | yes | yes | yes | yes |
| **§4.1** Anything else MUST be rejected as failed deprotection | yes | yes | yes | yes |
| **§4.2.1** SHOULD discard earlier-epoch records; MAY keep keys up to MSL | yes: keep prior matching epoch | partial | yes | yes |
| **§4.2.1** MAY buffer or discard app data before handshake done; MUST treat as in-order | yes: buffer until Finished | yes | yes | yes |
| **§4.2.1** Retransmits MUST use same epoch/keys | yes | yes | yes | yes |
| **§4.2.1** MUST abandon or rekey before sequence wrap | yes (`recordLimit`) | partial: 64-bit wrap only | yes | yes (48-bit) |
| **§4.2.1 / §6.1 / §8** MUST NOT wrap epoch; sender MUST NOT exceed 2^48−1; receiver MUST NOT enforce that cap | yes | partial: uint64 wrap, not 2^48−1 | yes | partial |
| **§4.2.2** SHOULD reconstruct seq as closest to 1+highest in epoch | yes | no: high bytes stay 0 after 8/16-bit SN decrypt | yes | yes |
| **§4.2.3** Ciphertext MUST be ≥16 bytes; senders MUST pad short plaintexts | yes reject; tx relies on 16-byte GCM/ChaCha tag, no extra inner pad | yes, including inner pad | yes | yes, pads to 16 |
| **§4.3** Each record MUST fit one datagram; records MUST NOT span datagrams; first byte MUST start a record | yes | yes | yes | yes |
| **§4.3** Multiple records MAY share a datagram | partial: rx yes, tx one record per datagram | rx yes; tx can pack | rx yes; tx typically one HS record | yes both |
| **§4.4** PMTU/ICMP/DF-bit SHOULD/MUST for UDP | no: `dtls-mtu` is static; no ICMP handling | no | no | no |
| **§4.4** Handshake SHOULD fragment immediately if too big; SHOULD back off record size after unanswered retries | yes fragment to MTU; no shrink-on-loss | yes fragment; backoff unclear | yes fragment | yes fragment |
| **§4.5.1** Replay check SHOULD use sliding window; MUST init at 0; MUST reject duplicates; MUST NOT update window until deprotect succeeds | yes (64-bit window after AEAD) | yes | yes (after AEAD) | yes |
| **§4.5.2** Invalid records SHOULD be silently discarded; fatal alerts NOT RECOMMENDED on UDP | partial: parse/auth/replay silent; some inner/handshake errors send alerts | yes drop | yes drop | yes drop |
| **§4.5.3** SHOULD NOT exceed AEAD confidentiality limit; SHOULD KeyUpdate before it | yes (GCM 2^24, ChaCha 2^48; KeyUpdate at limit−1024) | no | yes | no |
| **§4.5.3** MUST count AEAD auth failures; SHOULD close or KeyUpdate at 2^36 (GCM/ChaCha) | yes close at 2^36 | no | yes | no |
| **§4.5.3** `TLS_AES_128_CCM_8_SHA256` MUST NOT be used in DTLS without extra forgery protection | yes: suite rejected | no: advertised for DTLS 1.3 | yes: allowed with extra fail limit | yes: suite not present |

---

## RFC 9147 — handshake

| Req | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§5** MUST NOT echo `legacy_session_id`; MUST NOT send ChangeCipherSpec | yes | yes | yes (optional echo flag violates this) | yes |
| **§5.1** Client MUST send new ClientHello with cookie after HRR | yes | yes | yes | yes |
| **§5.1** Initial CH: omit cookie ext; `legacy_cookie` MUST be zero-length | yes | partial: client may echo HVR cookie; server does not abort nonempty `legacy_cookie` on 1.3 | yes abort nonempty | yes |
| **§5.1** Servers SHOULD cookie-exchange by default; MAY skip if amplification is not a threat | yes: always cookie | yes with `SSL_new_listener`; `s_server -listen` is DTLS 1.2 HVR | yes: 1.3 server requires HRR cookie | partial: stateful 20-byte cookie; skippable |
| **§5.1** SHOULD cap pre-validation output at 3× received bytes | yes | no | no | no (3× only in RRC) |
| **§5.1** Clients MUST be prepared to cookie-exchange every handshake | yes | yes | yes | yes |
| **§5.1** Invalid cookie MUST `illegal_parameter` | yes | partial | yes | yes |
| **§5.1** Second HRR MUST `unexpected_message` | yes | yes | yes | yes |
| **§5.1** Clients SHOULD still offer `connection_id` unless a profile says otherwise | yes (default on) | no | opt-in `WOLFSSL_DTLS_CID` | yes in CID examples |
| **§5.2** Transcript MUST be TLS Handshake (no DTLS seq/offset/length) | yes | yes | yes | yes |
| **§5.2** `message_seq` < next MUST discard; > next SHOULD queue | yes | yes | yes | yes |
| **§5.2** MUST NOT use HelloVerifyRequest for DTLS 1.3 | yes | yes (HVR is 1.2 only) | yes | yes (HVR is 1.2) |
| **§5.3** `legacy_version` MUST be {254,253}; 0xfefc is DTLS 1.3 | yes | yes | yes | yes |
| **§5.3** Empty `legacy_session_id` MUST unless cached pre-1.3 id | yes empty | yes | yes | yes |
| **§5.3** Nonempty `legacy_cookie` on DTLS 1.3 MUST `illegal_parameter` | yes | no | yes | yes |
| **§5.5** Fragments MUST NOT overlap on first send; MUST handle overlapping ranges; MUST NOT change bytes on retransmit; SHOULD abort if a byte changes | yes | yes | yes | yes |
| **§5.5** Each fragment MUST be in a single UDP datagram | yes | yes | yes | yes |
| **§5.6** EndOfEarlyData omitted; servers SHOULD NOT keep epoch 1 forever | n/a (no 0-RTT); unknown HS type rejected | yes omit EOED | yes reject EOED | n/a (no 0-RTT) |
| **§5.8.1** SHOULD omit already-ACKed fragments; timer then WAITING | yes | yes | yes | yes |
| **§5.8.1** Server MUST ACK client's final flight for ≥2×MSL | yes (4 min / twice default MSL) | yes | yes | yes |
| **§5.8.1** MUST discard or buffer epoch≥3 app data until peer Finished | yes | yes | yes | yes |
| **§5.8.2** SHOULD start at 1s, double to ≥60s | yes 1s→60s, 8 retries | yes | yes | yes |
| **§5.8.3** SHOULD NOT send more than 10 records in one transmission | yes (`flightBurst=10`) | unspecified | unspecified | packs more |
| **§5.8.4** MUST NOT send another KeyUpdate / NewConnectionId / RequestConnectionId until the previous is ACKed | yes | KeyUpdate yes; CID n/a | KeyUpdate yes; CID messages not sent | KeyUpdate yes; CID messages not sent |
| **§5.9** HKDF label prefix SHALL be `dtls13` (no trailing space) | yes | yes | yes | yes |
| **§5.10** Alerts SHOULD NOT be relied on; data after a valid close_notify MUST be ignored | yes | yes | yes | yes |
| **§5.11** New epoch-0 CH on an existing quartet: SHOULD handshake; MUST NOT destroy old association until cookie or Finished; after Finished MUST abandon previous | yes | yes | yes | yes |

---

## RFC 9147 — ACK, KeyUpdate, CID, security

| Req | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§7** MUST NOT ACK unprocessed/unbuffered handshake; MUST NOT ACK discarded future seq | yes | yes | yes | yes |
| **§7** Handshake ACK epoch MUST be ≥ record being ACKed; after HS MUST use highest sending epoch | yes | yes | yes | yes |
| **§7.1** Flights MUST be ACKed unless implicitly ACKed by the next flight | yes | partial: subset of disruption ACKs | yes | yes |
| **§7.1** MUST NOT ACK non-handshake or undeprotected records | yes | yes | yes | yes |
| **§7.2** SHOULD drop ACKed fragments from retransmit; MUST cancel flight when complete; any ACK of a record counts; responding flight MUST implicitly ACK | yes | partial: often retransmits whole flight | yes | yes |
| **§8** KeyUpdate MUST be ACKed; MUST NOT send with new keys or another KeyUpdate until ACK (erratum 8047, Reported) | yes | yes | yes | yes |
| **§8** MUST keep pre-update keys until a record decrypts with the new keys | yes | yes | yes | yes |
| **§8** `update_requested` MUST NOT force a KeyUpdate that would exceed epoch limit | yes | unspecified | yes | unspecified |
| **§9** `cid_immediate` MUST be used for all future records | yes | n/a | yes if received | n/a (not applied) |
| **§9** MUST NOT have more than one NewConnectionId outstanding | yes | n/a | n/a (never sent) | n/a |
| **§9** MUST NOT send NewConnectionId / RequestConnectionId if CID not negotiated or empty; MUST `unexpected_message` on violation | yes | n/a | rx Request ignored; NewConnectionId immediate only | codec only, rx unexpected |
| **§9** SHOULD respond to RequestConnectionId with spare CIDs; MUST NOT request while a request is outstanding | partial: we request and can issue spares; no auto-replenish after consume | no | no: Request ignored; spare discarded | no |
| **§9** SHOULD use a new CID on a new path | yes (RRC + spare) | no | no | RRC yes; CID not rotated |
| **§9.1** If no CID negotiated, records with CID MUST be rejected | yes | yes (C-bit discarded) | yes | yes |
| **§11** Cookie MUST depend on client address; MUST NOT be forgeable by others | yes HMAC(peer, …) | yes HMAC(addr\\|port\\|ts) | yes HMAC includes peer | no: random 20 bytes, stateful |
| **§11** Cookie SHOULD not allow reconstructing ClientHello | yes (hash/fingerprint) | yes | yes | n/a |
| **§11** MUST NOT update send address on a new source without a reachability test | yes (RFC 9853) | n/a (no CID/migration) | no RRC | yes (RFC 9853) |
| **§11** SHOULD NOT kill the connection on invalid records | partial: see §4.5.2 | yes | yes | yes |
| **§11** SHOULD use fresh CIDs when local address/port changes | yes request on migration | n/a | no | no |

---

## RFC 9146 — CID negotiation (DTLS 1.3 uses this extension; not the 1.2 record format)

| Req | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§3** Negotiate `connection_id`; once enabled, encrypted records MUST carry CID | yes | no | yes if `WOLFSSL_DTLS_CID` | yes if configured |
| **§6** MUST NOT replace peer address from a CID datagram unless the implementation has a validation procedure | yes: RFC 9853, not a silent swap | n/a | no validation procedure | yes: RRC |
| **§6** MUST silently discard bad MAC / invalid records | yes for MAC | yes | yes | yes |

RFC 9146 `tls12_cid` content type, DTLS 1.2 MAC/AEAD extra data, and
`retire_prior_to` are DTLS 1.2. Ours does not implement them. wolfSSL and
Pion have separate 1.2 CID paths.

---

## RFC 9853 — return-routability check

| Req | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§3** `rrc` only with CID; ignore if CID not negotiated | yes | no | no | yes |
| **§4** RRC MUST be encrypted in the active context | yes | n/a | n/a | yes |
| **§4** MUST parse path_challenge / path_response / path_drop; MUST ignore unknown types | yes | n/a | n/a | yes |
| **§5** On address change MUST stop or 3×-limit data to the unvalidated address and start RRC | yes | n/a | n/a | yes |
| **§5.2** Enhanced: challenge on preferred/old path; path_response MUST NOT switch; path_drop MUST fall back to basic | yes | n/a | n/a | yes |
| **§5.3** path_challenge MUST be random; SHOULD be in different packets | yes 8-byte cookie | n/a | n/a | yes |
| **§5.4** MUST NOT delay response; exactly one response per challenge; send it to the challenge source; silently discard invalid responses | yes | n/a | n/a | yes |
| **§5.5** Timer SHOULD be 3×RTT or 1s | yes: 1s (no RTT estimator) | n/a | n/a | yes: 1s |
| **§9** SHOULD avoid the same CID on multiple paths | yes request/rotate | n/a | n/a | partial: no CID rotate |

---

## RFC 10024 — ML-KEM hybrids

| Req | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§4.2** Server MUST ML-KEM encaps-key check; fail → `illegal_parameter` | yes (Go `mlkem`) | yes | yes | yes (X25519MLKEM768 only) |
| **§4.2** Client MUST check ciphertext length; other decaps failure → `internal_error` | yes | yes | yes | yes |
| **§4.2 / §4.3** ECDHE half MUST use RFC 9846 checks including X25519 all-zero | yes | yes | yes | yes |
| **§7** X25519 hybrid puts ML-KEM first; NIST hybrids put ECDHE first | yes | yes | yes | X25519MLKEM768 only |

---

## TLS ML-DSA (`draft-ietf-tls-mldsa-05`)

| Req | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§3.2** CertificateVerify uses TLS 1.3 context string; ML-DSA context is empty and distinct | yes | yes | yes | n/a (no ML-DSA) |
| **§3.2** End-entity cert MUST use the matching AlgorithmIdentifier | yes (Go x509) | yes | yes | n/a |

---

## RFC 9846 §1.2 — TLS 1.3 deltas that apply to us

Inherited TLS 1.3 handshake/record crypto is implemented except the rows
marked n/a. These are the §1.2 technical changes:

| Change | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| Forbid KeyShare reuse across connections | yes (fresh shares) | yes | yes | yes |
| Forbid TLS 1.0/1.1 | n/a (DTLS 1.3 only) | yes (TLS) | yes | yes |
| Clients ignore NewSessionTicket if no resumption | yes: ACK and drop | n/a (resumption exists) | n/a | yes: ticket queued, not used on 1.3 |
| Key-update-before-limit upgraded to MUST | yes | no DTLS counters | yes | no |
| Limit number of KeyUpdates | yes (epoch 2^48−1) | partial | yes | partial |
| `close_notify` is warning | yes | yes | yes | yes |
| `user_canceled` ignored; still send `close_notify` | yes ignore 90 | yes | yes | yes |
| `general_error` alert | no dedicated mapping | yes | unspecified | unspecified |
| CertificateRequest.extensions lower bound 0 | yes | yes | yes | yes |
| Remove RSA-PSS requirement | yes (ECDSA/Ed25519/ML-DSA work) | yes | yes | yes |

Deliberately not implemented, so the corresponding TLS 1.3 MUSTs are **n/a
until the feature exists**: PSK, resumption, 0-RTT, post-handshake client
authentication, DTLS 1.0/1.2, Encrypted Client Hello.

---

## Interop: what we can actually test

Pins and passing cases remain those in [dtls13.md](#independent-peers). This
section is about *coverage*, not a claim that every row above was
runtime-tested.

| Area | OpenSSL 4.1 | wolfSSL | Pion |
| --- | --- | --- | --- |
| Mutual cert, AES-GCM/ChaCha, classical groups | yes both roles | yes our client; CID tests both roles | yes both roles (drivers) |
| X25519MLKEM768 / NIST hybrids | yes at MTU 4096 | yes our client at MTU 4096; first CH must be unfragmented | X25519MLKEM768 only |
| ML-DSA-44/65/87 | yes mutual | library yes; not in our interop matrix | no |
| Fragmented first ClientHello | listener cookie path expects a usable first fragment | **rejects** unverified fragmented CH (even with `WOLFSSL_DTLS_CH_FRAG`) | yes |
| Cookies / 3× amplification | HMAC cookie; no 3× cap | HMAC cookie; no 3× cap | stateful cookie; no HS 3× |
| ACK / KeyUpdate | yes; partial-flight ACK + small MTU PQ is a known fail | yes; CID tests include KeyUpdate | yes |
| CID request / new / spare | **no DTLS 1.3 CID at all** | parse Request, ignore; spare discarded; immediate replace works | codec only; `ErrNotImplemented` on send |
| RFC 9853 RRC | no | no | yes both roles with **initial** CIDs |
| PSK / 0-RTT / resumption | yes in OpenSSL | yes in wolfSSL | 1.2 PSK only |
| Production MTU 1200 + PQ ClientHello | blocked by peer ACK/CH-frag limits | blocked by unfragmented-CH rule | not independently proven |

Practical consequences:

1. **Certificate DTLS 1.3 with GCM/ChaCha is the common core.** That is what
   `TestInteropOpenSSLClient`, `TestInteropWolfSSLServer`, and the Pion
   drivers cover.
2. **CID lifecycle cannot be tested against OpenSSL.** Against wolfSSL we can
   test *our* request + immediate rotation; we cannot test spare issuance or
   RFC 9147 §9 replenishment. Against Pion, public endpoints that request
   spares do not fully interoperate (Pion rejects CID-management messages).
3. **RRC/migration can only be tested against Pion**, and only with the
   initial handshake CID, not with mid-association CID rotation.
4. **PQ at MTU 1200 is not a three-stack result.** Ours fragments CH0
   correctly; wolfSSL will not reassemble it before the cookie; OpenSSL's
   listener path is similarly first-fragment sensitive; OpenSSL also
   mishandles some small-MTU ACK cases.
5. **Do not use `openssl s_server -listen` as a DTLS 1.3 cookie peer.** That
   flag is `DTLSv1_listen` (HelloVerifyRequest). Use `SSL_new_listener` /
   `demos/dtlslistenerecho`.
6. Shared Pion key-derivation/AES code means Pion interop will not catch
   bugs in that adapted crypto. Handshake FSM, cookies, CID, AEAD limits,
   and packing policy already diverge.

---

## How far along we are

Relative to **certificate-authenticated DTLS 1.3 over UDP**, this tree is
the most complete of the four for the RFC 9147+9146+9853 combination:

- Record protection, unified header (receive), SN encryption, replay,
  cookies, fragmentation, ACKs, KeyUpdate-after-ACK, CID request/new,
  enhanced RRC, ML-KEM hybrids, ML-DSA, AEAD limits, CCM_8 refusal.

Still short of a "full" RFC 9147 implementation:

| Gap | Spec | Why it matters |
| --- | --- | --- |
| PSK, resumption, 0-RTT, post-handshake client auth | 9147 / 9846 | large TLS 1.3 surface; OpenSSL/wolfSSL can test it, we cannot |
| Send compact unified header (8-bit SN, omit length) | 9147 §4 MAY | receive-only; all four stacks send the long form |
| Multiple records per outgoing datagram | 9147 §4.3 MAY | receive-only |
| Inner padding for short ciphertext | 9147 §4.2.3 MUST | vacuous with 16-byte tags; would matter for CCM_8 |
| PMTU/ICMP | 9147 §4.4 SHOULD/MUST | none of the four do this on UDP |
| AEAD-failure close is ours+wolfSSL only | 9147 §4.5.3 | OpenSSL/Pion will not exercise this against us |
| Spare-CID auto-replenish | 9147 §9 SHOULD | no independent peer issues spares |
| Cookie key rotation with overlapping secrets | 9147 §5.1 RECOMMENDED | single listener key |
| RFC 9846 `general_error` | 9846 §1.2 | unused |
| Erratum 8047 still **Reported** | 9147 §8 | we follow it; treat as non-normative until verified |

Of the four stacks, **ours is the only one that implements CID management
messages and RFC 9853 together.** That is also why those features are the
hardest to test: OpenSSL has neither; wolfSSL has handshake CID but not
request/new/RRC; Pion has RRC but stubs CID updates.

Ordinary `make check` does not download these peers. Linux interop remains:

```sh
python3 scripts/dtls13-lab.py
SOCAT_DTLS13_TOOLS="$HOME/socat-dtls13-lab/tools.json" \
  go test -tags dtlsinterop ./internal/dtls13 -run TestInterop -v
```
