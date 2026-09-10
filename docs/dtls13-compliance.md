# DTLS 1.3 requirement matrix

Peer source review: 2026-09-08; targeted follow-up: 2026-09-10.
Each row covers one requirement or capability.
Details and exceptions follow each table.

This is a selected requirements review, not a complete TLS/DTLS security audit.
The [standards list](dtls13-standards.md) defines its scope. Runtime results
are in [Independent peers](dtls13.md#independent-peers) and
[Default settings](dtls13.md#default-settings).

## Reading the tables

| Verdict | Meaning |
| --- | --- |
| yes | The reviewed implementation meets this requirement |
| no | The reviewed implementation does not meet this requirement |
| partial | Meets it only in some cases; see the notes below the table |
| unknown | The review did not establish a verdict |
| n/a | The requirement depends on an unsupported feature |

Verdicts describe the libraries at these [pins](../scripts/dtls13-baseline.json).
Unless a row says "by default", optional features are assessed when enabled.
`unknown` is not a failure, and `n/a` is not a pass. A `no` for a SHOULD
records a departure from the recommendation, not a MUST violation.

| Stack | Reviewed source |
| --- | --- |
| Ours | This tree: `internal/dtls13` |
| OpenSSL | `82733d9`, 4.1 development snapshot |
| wolfSSL | `d72f6d9` |
| Pion | `59f4c33` |

## RFC 9147 — record headers and sequence numbers

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§4** Plaintext sequence number MUST stay below 2^48 | yes | yes | yes | yes |
| **§4** Sender MUST use legacy record version {254,253} | yes | yes | yes | yes |
| **§4** Receiver MUST ignore the legacy record version | yes | yes | yes | yes |
| **§4** A record without a length MUST be last in its datagram | yes | yes | yes | yes |
| **§4** Datagrams MUST carry the negotiated CID | yes | n/a | yes | yes |
| **§4** A datagram MUST NOT mix associations | yes | n/a | yes | yes |
| **§4** A later mismatched CID MUST discard the rest of the datagram | yes | n/a | yes | yes |
| **§4.1** First byte 21, 22 or 26 MUST select DTLSPlaintext | yes | yes | yes | yes |
| **§4.1** Leading bits 001 MUST select DTLSCiphertext | yes | yes | yes | yes |
| **§4.1** Other record prefixes MUST be rejected | yes | yes | yes | yes |
| **§4.2.1** Earlier-epoch records SHOULD be discarded | yes | partial | yes | yes |
| **§4.2.1** Early application data MUST be processed as if received in order | yes | yes | yes | yes |
| **§4.2.1** Retransmissions MUST use the original epoch and keys | yes | yes | yes | yes |
| **§4.2.1** Sender MUST close or rekey before sequence-number wrap | yes | partial | yes | yes |
| **§4.2.1** Epoch numbers MUST NOT wrap | yes | yes | yes | yes |
| **§8** Sender MUST NOT use epochs above 2^48−1 | yes | no | yes | yes |
| **§8** Receiver MUST NOT enforce the sender's epoch cap | yes | yes | yes | no |
| **§4.2.2** Reconstructed sequence SHOULD be closest to 1 + highest received | yes | no | yes | yes |
| **§4.2.3** Receiver MUST reject ciphertext shorter than 16 bytes | yes | yes | yes | yes |
| **§4.2.3** Sender MUST pad if needed to reach 16 ciphertext bytes | yes | yes | yes | yes |
| **§4.3** Each record MUST fit in one datagram | yes | yes | yes | yes |
| **§4.3** A datagram's first byte MUST start a record | yes | yes | yes | yes |

The initial ClientHello may use legacy record version {254,255}. All four
stacks accept 8- and 16-bit sequence fields and transmit 16-bit fields. All
four accept omitted record lengths; their senders include the length.
Our sender uses one record per datagram. These are permitted choices.

Our stack retains matching earlier-epoch keys where the protocol allows it
and discards application data until the peer's Finished. Its 16-byte AEAD
tags satisfy the minimum ciphertext size without extra padding.

OpenSSL's sequence-wrap protection is limited to its 64-bit counter, and
its sequence reconstruction leaves the high bytes zero after decrypting the
short field. Earlier-epoch handling is incomplete.

OpenSSL detects epoch overflow and
[terminates before installing new keys](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/tls13_enc.c#L943).
Its [64-bit epoch counter](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/rec_layer_d1.c#L825)
has no 2^48 sender cap. Pion
[rejects the next generation at epoch 65535](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/internal/handshake/post_handshake.go#L592)
on both send and receive. That prevents wrap and keeps its sender below
the limit, but also imposes a stricter limit on the peer's epochs.

## RFC 9147 — path MTU

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§4.4** SHOULD expose the IP layer's PMTU estimate | no | yes | no | no |
| **§4.4** SHOULD expose record overhead or the resulting payload limit | yes | yes | yes | no |
| **§4.4** MUST report transport "packet too big" errors to the upper layer | yes | yes | partial | yes |
| **§4.4** SHOULD let the application control IP fragmentation | yes | yes | yes | yes |
| **§4.4** Handshake SHOULD fragment messages that exceed the path MTU | yes | yes | yes | yes |
| **§4.4** Handshake SHOULD shrink records after unanswered retries (PMTU unknown) | yes | yes | no | no |

Our `MaxDatagramSize()` reports the payload limit after record overhead;
it does not query the OS PMTU. Application writes preserve transport errors.
The handshake fragments on oversize errors and reduces size after a second
unanswered retry. See [PMTU behavior](dtls13.md#pmtu-invariants).

Applications own the supplied socket and can configure fragmentation.
`UnfragmentedProbes` also enables DF on eligible dedicated clients; shared
listeners do not change DF.

OpenSSL provides a [PMTU query](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/crypto/bio/bss_dgram.c#L656),
[DF control](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/crypto/bio/bss_dgram.c#L909)
and [handshake MTU-error handling](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/statem/statem_dtls.c#L342).
[`DTLS_get_data_mtu`](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/d1_lib.c#L1151)
accounts for DTLS 1.3 record overhead. Its
[timeout handler](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/d1_lib.c#L551)
reduces the MTU after two unsuccessful retransmissions, unless MTU queries
are disabled; retransmissions use that smaller budget.

wolfSSL exposes
[`wolfSSL_GetMaxOutputSize` and `wolfSSL_GetOutputSize`](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/ssl.c#L1557).
It reports send failures, but its
[socket error translation](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/wolfio.c#L201)
maps `EMSGSIZE` to a generic I/O error. The caller cannot identify the
PMTU failure from that error, so the verdict is `partial`. Pion
[preserves packet-connection write errors](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/conn.go#L779).
Neither library queries the OS PMTU or shrinks records on timeout.
Pion's [`WithMTU`](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/options.go#L363)
sets a size budget; it does not report negotiated record overhead.

Both let applications configure DF on the supplied transport:
[wolfSSL socket descriptor](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/ssl.c#L1100),
[Pion packet connection](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/conn.go#L497).
A dedicated DF helper is not required for this capability.

## RFC 9147 — replay and record protection

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§4.5.1** Replay detection SHOULD use a sliding window | yes | yes | yes | yes |
| **§4.5.1** The received-record counter MUST start at zero | yes | yes | yes | yes |
| **§4.5.1** Duplicate sequence numbers MUST be rejected | yes | yes | yes | yes |
| **§4.5.1** The replay window MUST NOT advance before successful decryption | yes | yes | yes | yes |
| **§4.5.2** Invalid records SHOULD be silently discarded | partial | partial | partial | partial |
| **§4.5.2 / §11** Invalid records SHOULD NOT terminate a UDP association | partial | partial | partial | partial |
| **§4.5.3** Sender SHOULD stay within the AEAD confidentiality limit | yes | no | yes | no |
| **§4.5.3** Sender SHOULD update keys before the confidentiality limit | yes | no | yes | no |
| **§4.5.3** Receiver MUST count AEAD authentication failures | yes | no | yes | no |
| **§4.5.3** Receiver SHOULD close or rekey at 2^36 GCM/ChaCha failures | yes | no | yes | no |
| **§4.5.3** CCM_8 MUST NOT be used without extra forgery protection | yes | no | yes | yes |

All four stacks drop bad MACs and replayed records but can abort on errors
inside authenticated content. That makes the silent-discard verdicts
`partial`. RFC 9147 permits fatal alerts, although it recommends avoiding
them on UDP. Examples:
[ours](../internal/dtls13/session.go),
[OpenSSL](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/methods/tls_common.c#L1053),
[wolfSSL](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/internal.c#L24560)
and [Pion](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/conn.go#L2219).
Our stack also discards malformed ACK bodies.

Our per-key limits are 2^24 AES-GCM records and 2^48 ChaCha20 records;
application writes trigger KeyUpdate 1024 records earlier. The receive side
closes at 2^36 authentication failures. These limits are separate from
sequence-number wrap protection.

Our stack rejects CCM_8 and Pion does not provide it. wolfSSL permits it
with an extra failure limit. OpenSSL advertises it without that protection.

## RFC 9147 — handshake

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§5** Server MUST NOT echo `legacy_session_id` | yes | yes | partial | yes |
| **§5** MUST NOT send ChangeCipherSpec | yes | yes | yes | yes |
| **§5.1** Client MUST send a new ClientHello after HelloRetryRequest | yes | yes | yes | yes |
| **§5.1** Client MUST return the HelloRetryRequest cookie | yes | yes | yes | yes |
| **§5.1** Initial ClientHello MUST omit the cookie extension | yes | yes | yes | yes |
| **§5.1** Initial ClientHello MUST have an empty `legacy_cookie` | yes | partial | yes | yes |
| **§5.1** Server SHOULD require a cookie exchange by default | yes | partial | yes | partial |
| **§5.1** Pre-validation output SHOULD stay within 3× received bytes | yes | no | no | no |
| **§5.1** Client MUST support a cookie exchange on every handshake | yes | yes | yes | yes |
| **§5.1** Invalid cookies MUST cause `illegal_parameter` | yes | partial | yes | yes |
| **§5.1** Cookie-secret lifetimes SHOULD overlap | yes | no | yes | n/a |
| **§5.1** A second HelloRetryRequest MUST cause `unexpected_message` | yes | yes | yes | yes |
| **§5.1** Client SHOULD offer CID by default unless its profile excludes it | yes | no | no | no |
| **§5.2** The transcript MUST exclude DTLS sequence and fragment fields | yes | yes | yes | yes |
| **§5.2** Handshake messages below the expected sequence MUST be discarded | yes | yes | yes | yes |
| **§5.2** Handshake messages above the expected sequence SHOULD be queued | yes | yes | yes | yes |
| **§5.2** MUST NOT use HelloVerifyRequest in DTLS 1.3 | yes | yes | yes | yes |
| **§5.3** ClientHello MUST use legacy version {254,253} | yes | yes | yes | yes |
| **§5.3** Session ID MUST be empty unless it identifies a cached pre-1.3 session | yes | yes | yes | yes |
| **§5.3** Server MUST reject a nonempty `legacy_cookie` with `illegal_parameter` | yes | no | yes | yes |
| **§5.5** Fragments MUST NOT overlap on their first transmission | yes | yes | yes | yes |
| **§5.5** Receiver MUST handle overlapping fragment ranges | yes | yes | yes | yes |
| **§5.5** Retransmitted handshake bytes MUST NOT change | yes | yes | yes | yes |
| **§5.5** Receiver SHOULD abort if a retransmitted byte changes | yes | yes | yes | yes |
| **§5.5** Each handshake fragment MUST fit in one datagram | yes | yes | yes | yes |
| **§5.6** EndOfEarlyData MUST be omitted | n/a | yes | yes | n/a |
| **§5.6** Server SHOULD limit acceptance of late epoch-1 data | n/a | yes | yes | n/a |
| **§5.8.1** Retransmission timer expiry returns the sender to WAITING | yes | yes | yes | yes |
| **§5.8.1** Server MUST ACK the client's final flight for at least 2×MSL | yes | yes | yes | yes |
| **§5.8.1** Epoch-3 application data MUST wait until the peer's Finished | yes | yes | yes | yes |
| **§5.8.2** Initial retransmission timeout SHOULD be one second | yes | yes | yes | yes |
| **§5.8.2** Retransmission timeout SHOULD double, up to at least 60 seconds | yes | yes | yes | yes |
| **§5.8.2** An unambiguous ACK SHOULD set the timeout to 1.5×RTT | yes | no | no | no |
| **§5.8.3** A transmission SHOULD contain at most ten records | yes | no | no | no |
| **§5.9** HKDF labels SHALL use the `dtls13` prefix | yes | yes | yes | yes |
| **§5.10** Implementations SHOULD NOT rely on alert delivery | yes | yes | yes | yes |
| **§5.10** Application data after valid `close_notify` MUST be ignored | yes | yes | yes | yes |
| **§5.11** A new epoch-0 ClientHello on an existing address SHOULD start a handshake | yes | yes | yes | yes |
| **§5.11** The old association MUST survive until a valid cookie or Finished | yes | yes | yes | yes |
| **§5.11** Successful Finished MUST replace the old association | yes | yes | yes | yes |

wolfSSL can echo the session ID under an optional flag. OpenSSL's legacy
cookie handling includes DTLS 1.2 HelloVerifyRequest behavior; its DTLS 1.3
server does not reject a nonempty legacy cookie. Its
[cookie-extension writer](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/statem/extensions_clnt.c#L1018)
omits the extension until a HelloRetryRequest supplies a cookie.

OpenSSL's `SSL_new_listener` performs DTLS 1.3 cookies; `s_server -listen`
uses the DTLS 1.2 exchange. Pion uses a stateful, skippable cookie exchange.
Our server always requires cookies. It rotates HMAC secrets every 60 seconds
and retains the previous secret for one rotation; cookie age still expires
after 60 seconds.

OpenSSL uses [one cookie HMAC key per context](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/ssl_lib.c#L4557),
without rotation or an overlap mechanism. wolfSSL supports overlap through
[`wolfSSL_set_hrr_cookie_secret_secondary`](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/tls13.c#L16199);
[`TlsCheckCookie`](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/tls13.c#L7249)
tries that secret if the current one fails. The application manages rotation.

wolfSSL CID requires `WOLFSSL_DTLS_CID`. Pion leaves its CID generator unset
in [default configuration](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/options.go#L86);
[`WithConnectionID`](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/options.go#L486)
enables it.

The epoch-1 rule limits how long servers accept early data after epoch 3
becomes usable. OpenSSL [frees the old read record layer when replacing it](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/rec_layer_s3.c#L1588).
wolfSSL [rejects epoch-1 records after handshake completion](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/internal.c#L13151),
even while the old key slot remains allocated.

The ten-record recommendation covers a transmission across datagrams.
[OpenSSL](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/statem/statem_dtls.c#L240)
and [wolfSSL](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/dtls13.c#L1042)
send all fragments without a ten-record limit. wolfSSL's
[retransmission loop](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/dtls13.c#L1646)
also resends stored fragments without shrinking them. Pion
[writes every prepared datagram](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/conn.go#L779)
with no such limit.

Our final-flight ACK retention is four minutes. Retransmission starts at
one second, doubles to 60 seconds, and allows eight retries. RTT samples
exclude retransmissions; the resulting timer has a 100 ms floor.

## RFC 9147 — ACKs and KeyUpdate

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§7** MUST NOT ACK handshake data that was neither processed nor buffered | yes | yes | yes | yes |
| **§7** MUST NOT ACK discarded future-sequence messages | yes | yes | yes | yes |
| **§7** Handshake ACK epoch MUST be at least the acknowledged record's epoch | yes | yes | yes | yes |
| **§7** Post-handshake ACKs MUST use the highest sending epoch | yes | yes | yes | yes |
| **§7.1** Flights MUST receive an ACK unless the next flight implicitly ACKs them | yes | partial | yes | yes |
| **§7.1** MUST NOT ACK non-handshake records | yes | yes | yes | yes |
| **§7.1** MUST NOT ACK records that failed decryption | yes | yes | yes | yes |
| **§5.8.1 / §7.2** Retransmissions SHOULD omit acknowledged fragments | yes | partial | yes | yes |
| **§7.2** A fully acknowledged flight MUST stop retransmitting | yes | partial | yes | yes |
| **§7.2** A record acknowledged by any ACK MUST remain acknowledged | yes | partial | yes | yes |
| **§7.2** A responding record MUST implicitly ACK the preceding flight | yes | partial | yes | yes |
| **§8** KeyUpdate MUST be acknowledged | yes | yes | yes | yes |
| **§8** Sender MUST wait for the KeyUpdate ACK before using the new keys | yes | yes | yes | yes |
| **§5.8.4 / §8** Sender MUST wait for an ACK before another KeyUpdate | yes | yes | yes | yes |
| **§8** Receiver MUST retain old keys until it decrypts with the new keys | yes | yes | yes | yes |
| **§8** A requested KeyUpdate MUST NOT exceed the epoch limit | yes | no | yes | yes |

Our responding flights provide implicit ACKs. The client's final flight and
post-handshake messages use explicit ACKs. OpenSSL
[rejects ACKs in `TLS_ST_SW_FINISHED`](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/statem/statem_srvr.c#L114).
Where ACKs are accepted, [processing one](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/statem/statem_dtls.c#L1264)
[stops the timer](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/statem/statem.c#L722)
and clears the entire sent flight, even for a partial ACK. Retransmissions
[discard previous record-number mappings](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/statem/statem_dtls.c#L1486)
and resend whole messages. These paths do not reliably track individual
fragments across retransmissions.

OpenSSL also clears the preceding flight when it finishes reading the
responding flight; it does not do so on every individual responding record.
Its epoch increment lacks the sender cap for requested KeyUpdates too.
Pion checks its 16-bit limit before constructing any KeyUpdate, including
a response to the peer.

Post-handshake ordering follows [erratum 8047](https://www.rfc-editor.org/errata/eid8047),
which was **Reported**, not verified, at the review date.

## RFC 9147 — connection IDs and migration

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§9** Receiver MUST use `cid_immediate` for subsequent records | yes | n/a | yes | n/a |
| **§5.8.4 / §9** Sender MUST wait for an ACK before another NewConnectionId | yes | n/a | n/a | n/a |
| **§5.8.4** Sender MUST wait for an ACK before another RequestConnectionId | yes | n/a | n/a | n/a |
| **§9** CID updates MUST NOT be sent without a negotiated, nonempty CID | yes | n/a | n/a | n/a |
| **§9** Unnegotiated NewConnectionId MUST cause `unexpected_message` | yes | n/a | yes | yes |
| **§9** Unnegotiated RequestConnectionId MUST cause `unexpected_message` | yes | n/a | yes | yes |
| **§9** Receiver SHOULD answer CID requests with spares | yes | n/a | no | no |
| **§9** Sender MUST wait for fulfillment before requesting more CIDs | yes | n/a | n/a | n/a |
| **§9** Sender SHOULD use a new CID on a new path | yes | n/a | no | no |
| **§9.1** Receiver MUST reject CIDs if none was negotiated | yes | yes | yes | yes |
| **§11** Cookies MUST depend on the client address | yes | yes | yes | yes |
| **§11** Cookies MUST resist forgery | yes | yes | yes | yes |
| **§11** A cookie SHOULD NOT reveal the original ClientHello | yes | yes | yes | n/a |
| **§11** Sender MUST validate reachability before changing the peer address | yes | n/a | no | yes |
| **§11** Sender SHOULD use fresh CIDs after a local address or port change | yes | n/a | no | no |

OpenSSL has no DTLS 1.3 CID support. wolfSSL accepts immediate updates but
ignores requests and discards spares. Pion has message codecs but rejects
CID-management messages; its send operations are unimplemented. Neither
peer issues spares. Sources:
[wolfSSL](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/dtls13.c#L2993),
[Pion](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/internal/handshake/post_handshake.go#L267).

wolfSSL's [shared message check](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/tls13.c#L14960)
rejects both CID-management messages when CID was not negotiated;
[the caller sends `unexpected_message`](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/tls13.c#L15047).
Ignoring requests applies only after negotiation.

Our ACK alone does not fulfill a spare request. A full issuer pool rotates
an ID before issuing more; authenticated use retires the old IDs. Tests:
[`TestCIDACKWithoutResponseRemainsPending` and `TestCIDEmptySpareResponseFulfillsRequest`](../internal/dtls13/connection_id_test.go).

Pion binds a stored random 20-byte cookie to the client 5-tuple. A different
address selects a different association, so a cookie need not use HMAC to
meet the address-binding rule. Sources:
[cookie storage](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/internal/flight/flight13/flight2handler.go#L47),
[association lookup](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/internal/net/udp/packet_conn.go#L247).

## RFC 9146 — CID negotiation

Only the extension applies here. DTLS 1.2's `tls12_cid` record format and
MAC/AEAD encoding do not apply to DTLS 1.3.

| Requirement or capability | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§3** Supports the `connection_id` extension | yes | no | yes | yes |
| **§6** MUST NOT replace the peer address without a validation procedure | yes | n/a | no | yes |

wolfSSL needs the CID build option; Pion needs CID configuration.

## RFC 9853 — return-routability checks

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§3** Supports the `rrc` extension | yes | no | no | yes |
| **§3** RRC MUST depend on CID negotiation | yes | n/a | n/a | yes |
| **§3** Receiver MUST ignore `rrc` when CID was not negotiated | yes | n/a | n/a | yes |
| **§4** RRC messages MUST be encrypted in the active context | yes | n/a | n/a | yes |
| **§4** Receiver MUST parse the three defined RRC message types | yes | n/a | n/a | yes |
| **§4** Receiver MUST ignore unknown RRC message types | yes | n/a | n/a | yes |
| **§5** An address change MUST trigger reachability validation | yes | n/a | n/a | yes |
| **§5** Data to an unvalidated address MUST stop or stay within the 3× limit | yes | n/a | n/a | yes |
| **§5.2** Enhanced validation challenges the preferred path first | yes | n/a | n/a | yes |
| **§5.2** A preferred-path response MUST NOT switch paths | yes | n/a | n/a | yes |
| **§5.2** A preferred-path `path_drop` MUST start basic validation | yes | n/a | n/a | yes |
| **§5.3** Challenge cookies MUST be random | yes | n/a | n/a | yes |
| **§5.3** Challenges SHOULD use different packets | yes | n/a | n/a | yes |
| **§5.4** Responses MUST NOT be delayed | yes | n/a | n/a | yes |
| **§5.4** Each valid challenge MUST receive exactly one response | yes | n/a | n/a | yes |
| **§5.4** Responses MUST go to the challenge's source address | yes | n/a | n/a | yes |
| **§5.4** Invalid responses MUST be silently discarded | yes | n/a | n/a | yes |
| **§5.5** Validation timeout SHOULD use 3×RTT when RTT is known | partial | n/a | n/a | no |
| **§5.5** Validation timeout SHOULD use one second when RTT is unknown | yes | n/a | n/a | yes |
| **§9** Sender SHOULD avoid reusing a CID across paths | yes | n/a | n/a | no |

Our old-path timer uses 3×RTT with a 100 ms floor; the unmeasured candidate
path gets at least one second. The floor makes the known-RTT verdict
`partial`. Pion [always sets the timer to one second](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/internal/rrc/rrc.go#L183).
Pion validates migration using initial CIDs but does not
rotate them between paths.

## RFC 10024 — ML-KEM hybrids

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§4.2** Server MUST reject invalid ML-KEM encapsulation keys with `illegal_parameter` | yes | yes | yes | yes |
| **§4.2** Client MUST check ciphertext length | yes | yes | yes | yes |
| **§4.2** Other decapsulation failures MUST cause `internal_error` | yes | yes | yes | yes |
| **§4.2 / §4.3** ECDHE MUST perform the TLS 1.3 public-key checks | yes | yes | yes | yes |
| **§7** X25519 hybrids encode ML-KEM before ECDHE | yes | yes | yes | yes |
| **§7** NIST-curve hybrids encode ECDHE before ML-KEM | yes | yes | yes | n/a |

Pion's verdicts cover X25519MLKEM768 only. Our ML-KEM validation uses Go's
`mlkem` implementation. The ECDHE checks include rejecting all-zero X25519
shared secrets.

## TLS ML-DSA — draft-ietf-tls-mldsa-05

| Requirement | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| **§3.2** CertificateVerify uses the TLS 1.3 context string | yes | yes | yes | n/a |
| **§3.2** The separate ML-DSA context is empty | yes | yes | yes | n/a |
| **§3.2** End-entity certificates MUST use the matching AlgorithmIdentifier | yes | yes | yes | n/a |

These are library verdicts. The wolfSSL lab binaries cannot load ML-DSA
certificates; independent ML-DSA interop was run against OpenSSL.

## RFC 9846 — selected TLS 1.3 changes

This covers selected §1.2 changes and §4.7.3, not every inherited TLS rule.

| Requirement or capability | Ours | OpenSSL | wolfSSL | Pion |
| --- | --- | --- | --- | --- |
| Key shares MUST NOT be reused across connections | yes | yes | yes | yes |
| TLS 1.0 and 1.1 MUST NOT be used | n/a | yes | yes | yes |
| Clients without resumption support ignore NewSessionTicket | yes | n/a | n/a | yes |
| Sender MUST update keys before the AEAD usage limit | yes | no | yes | no |
| The number of KeyUpdates is bounded | yes | partial | yes | partial |
| **§4.7.3** Another `update_requested` MUST wait for a peer KeyUpdate | yes | no | no | no |
| `close_notify` uses warning severity | yes | yes | yes | yes |
| `user_canceled` is ignored | yes | yes | yes | yes |
| `close_notify` is still sent after `user_canceled` | yes | yes | yes | yes |
| Treats `general_error` as fatal regardless of severity | yes | yes | yes | no |
| CertificateRequest permits an empty extensions vector | yes | yes | yes | yes |
| Authentication can work without RSA-PSS | yes | yes | yes | yes |

Our KeyUpdate count is bounded by the 2^48−1 epoch limit. A DTLS ACK does
not clear `update_requested`; only a later peer KeyUpdate does. OpenSSL's
[`SSL_key_update`](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/ssl_lib.c#L3142)
and Pion's [`UpdateKeys`](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/conn.go#L622)
allow another request after an ACK without waiting for a peer KeyUpdate.
wolfSSL's [`SendTls13KeyUpdate`](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/tls13.c#L13611)
overwrites its pending-response flag on every send. Three local updates,
each ACKed but without a peer KeyUpdate, send request flags 1, 0, 1.
Pion queues NewSessionTicket without using it for DTLS 1.3.

Our receiver recognizes `general_error` (117) and terminates the connection.
Sending a generic alert is optional; specific alerts or `internal_error`
remain valid choices.

OpenSSL [displays alert 117 as "unknown"](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/ssl_stat.c#L361),
but its [DTLS 1.3 receive path treats it as fatal at either severity](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/rec_layer_d1.c#L496).
wolfSSL [names alert 117](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/wolfssl/ssl.h#L1028)
and [treats it as fatal regardless of severity](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/internal.c#L24175).
Pion has [no named `general_error` value](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/pkg/protocol/alert/alert.go#L47).
It parses 117 as an unknown alert and closes only if the
[severity is fatal](https://github.com/pion/dtls/blob/59f4c33b90c58fa6256a9cf1db49d1a9976b3536/errors.go#L53).

## Interop: what we can actually test

Passing handshakes do not verify every matrix row. Test configurations,
MTUs, algorithms and failure details are maintained in
[Independent peers](dtls13.md#independent-peers); unpinned negotiation is in
[Default settings](dtls13.md#default-settings).

- OpenSSL covers mutual certificates, all three record suites, classical
  and hybrid groups, and ML-DSA. It cannot test DTLS 1.3 CID or migration.
- wolfSSL covers mutual certificates, hybrid groups, immediate CID rotation
  and KeyUpdate. It cannot test spare-CID issuance or RRC. Its unverified
  first ClientHello must remain unfragmented.
- Pion covers KeyUpdate and RRC with initial CIDs through the protocol
  drivers. Public-API hybrid tests disable CID because CID-management
  messages are rejected. Shared adapted crypto limits independence.

For OpenSSL DTLS 1.3 cookie tests, use `SSL_new_listener` or
`demos/dtlslistenerecho`; `s_server -listen` uses the DTLS 1.2 exchange.
wolfSSL hybrid tests at small MTUs use an empty first `key_share` and a
cookie-bearing retry. The detailed test results record the required flags.

## Remaining work and permitted choices

- Repeat the [routed Linux PMTU lab](dtls13.md#routed-linux-lab) after PMTU
  changes. Routed Windows/macOS validation needs suitable test environments.
- Test spare-CID issuance and replenishment against an independent peer
  when one supports it. Local renewal is implemented.
- Keep PSK, resumption, 0-RTT, post-handshake client authentication,
  DTLS 1.0/1.2 and Encrypted Client Hello outside this implementation's
  scope. Requirements conditional on these features are `n/a`.

An empty initial `key_share` is permitted by
[RFC 9846 §4.3.8](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.3.8).
Our client uses it when initial shares would fragment; if the empty hello
still cannot fit, it sends the original shares as fragments.

Ordinary `make check` does not download reference peers. Run Linux interop
separately:

```sh
python3 scripts/dtls13-lab.py
SOCAT_DTLS13_TOOLS="$HOME/socat-dtls13-lab/tools.json" \
  go test -tags dtlsinterop ./internal/dtls13 -run 'TestInterop|TestDefaultSettings' -v
```
