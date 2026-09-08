# DTLS 1.3

User options and examples are in the [README](../README.md#dtls-13).
RFCs and code map: [dtls13-standards.md](dtls13-standards.md).
BCP 14 matrix vs OpenSSL, wolfSSL, and Pion: [dtls13-compliance.md](dtls13-compliance.md).

Certificate-authenticated DTLS 1.3 over UDP on Linux, macOS and Windows:
cookies, SNI/ALPN, mutual authentication, fragmentation, selective ACKs,
retransmissions, replay protection, key updates, CID rotation and RFC 9853
enhanced path validation. Endpoints reuse the existing credentials, socket
options, peer filters, fork lifecycle, deadlines and cancellation.

Handshake MTU shrink is automatic. Command-line clients also default to MTU
confirmation and upward discovery on eligible dedicated sockets with CID/RRC.
`dtls-unfragmented-probes=0` disables discovery; the default ceiling stays
1200 bytes. Direct library callers opt in with `Config.UnfragmentedProbes`.

Algorithm defaults follow Go 1.27's TLS 1.3 preference order in
`defaultCipherSuites` and `defaultGroups`: AES-128/256-GCM and
ChaCha20-Poly1305; X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
X25519, P-256/P-384/P-521; RSA-PSS, ECDSA, Ed25519 and ML-DSA-44/65/87.
The TLS ML-DSA mapping follows `draft-ietf-tls-mldsa-05`. New algorithms still
need DTLS wire integration.

The stack adapts Pion's key derivation, AES protection and test vectors, not
its protocol framework. Keep the [NOTICE](../internal/dtls13/NOTICE.md) and
[MIT license](../internal/dtls13/LICENSE.pion). Pion interop cannot catch bugs
shared with that adapted code.

## Bounds

- Application delivery is unordered and unreliable; close alerts may be lost.
- Listener: 16 cookie-validated pending handshakes, 256 associations by
  default, 8 MiB queued input, 16 MiB reassembly. Unvalidated peers share a
  64-entry, 2 MiB plaintext retry cache and get no association, CID or
  per-peer goroutine. Pre-cookie output is capped at 3× received bytes.
  Migrated addresses pass the peer filter.
- Per association: 256 input slots (655350 bytes) and 256 application slots
  (256 KiB). Overflow is dropped. Reassembly: 1 MiB per message, 16 pending
  sequences, 2 MiB of bodies.
- CID pools hold eight identifiers plus one temporary identifier during
  immediate rotation. Low-spare requests run automatically. A full issuance
  pool rotates one CID immediately instead of sending an empty spare list;
  the spare request stays pending until that rotation is authenticated.
  Path probes pause issuance. Consuming a spare still does not retire older
  receive CIDs until immediate rotation is used.
- Not implemented: DTLS 1.0/1.2, PSK, resumption, 0-RTT, post-handshake
  client authentication. `EXEC,nofork` cannot use DTLS.

## PMTU invariants

- Linux/Windows use `PMTUDISC_PROBE`, not `DO`, to bypass stale path-MTU
  cache limits. macOS uses `DONTFRAG`.
- Discovery does not query `IP_MTU` or connect/reconnect the active DTLS socket.
- Automatic PMTU setup leaves shared listeners' fragmentation settings unchanged.
- The working MTU grows only after an authenticated response to a current
  discovery probe, within the configured `dtls-mtu` ceiling.

## Independent peers

Last interoperability runs: 2026-09-08 against master `8d84ad3`. Pins are in
[dtls13-baseline.json](../scripts/dtls13-baseline.json) and
[dtls13-lab.py](../scripts/dtls13-lab.py). Limits are for those revisions.

| Peer | Passing coverage | Limits |
| --- | --- | --- |
| OpenSSL 4.1 snapshot (`82733d9`) | 21 suite/group combinations (includes both NIST hybrids): our client at MTU 4096 (`TestInteropOpenSSLServer`); our listener at default MTU 1200 (`TestInteropOpenSSLClient`). Mutual ML-DSA-44/65/87 at MTU 4096. Small-MTU 1200/512/256 is ChaCha20-Poly1305 plus X25519MLKEM768 only: ECDSA and mutual ML-DSA-44/65/87 echo in both roles (`s_server` and `s_client`). Our client completed ML-DSA-44 echo after a dropped first ClientHello at those MTUs. Captured UDP payloads stayed within the configured MTU (our client max sent 1191/503/256; our listener max sent 1200/512/256). | No DTLS 1.3 CID. Cookie-listener (`SSL_new_listener`) is untested. OpenSSL may emit ACK lists larger than the MTU; malformed ACK bodies are discarded. NIST hybrids were not run at 1200/512/256. |
| wolfSSL master (`d72f6d9`) | 21 suite/group combinations with our client at MTU 4096. 12 mutual-auth CID cases in both roles (default MTU 1200, all suites, P-256, request ACKs, rotation with lost ACKs and KeyUpdate). | Rejects a fragmented unverified first ClientHello, so PQ at 1200/512/256 times out. No spare issuance/replenishment or RFC 9853 RRC. |
| Pion (`59f4c33`) | Mutual authentication, bidirectional KeyUpdate and rebinding/RRC in both roles through protocol drivers using initial CIDs. | Rejects CID-management messages. Migration-enabled public endpoints request spares and do not fully interoperate. Production-MTU PQ was not independently proven. |
| BoringSSL (`4a92579`) | Test shim builds. | Packet-BIO adapter and interop tests are not written. Lower priority; lab-only. |

The wolfSSL lab build enlarges its extra read buffer to 4096 bytes for hybrid
offers and still requires an unfragmented first ClientHello. OpenSSL `s_server`
accepted our fragmented X25519MLKEM768 ClientHello at 256 with ECDSA and
mutual ML-DSA echo.

None of the pinned peers supplies independent spare-CID issuance coverage.
System OpenSSL 3.5.5 is DTLS 1.2 only (`s_client` has no `-dtls1_3`). OpenSSL
4.1 is still unreleased (planned October 2026); 4.0 has no DTLS 1.3.
Unmodified classic socat 1.8.1.3 (`12c08bf`) fails to compile against the
pinned OpenSSL 4.1 headers (`ASN1_OCTET_STRING` is an incomplete type in
`xio-openssl.c`). Keep lab builds separate from system libraries and the
[classic parity baseline](../scripts/classic-baseline.json). The TLS ML-DSA
mapping is still `draft-ietf-tls-mldsa-05` (IESG approved, RFC not published).

## Remaining work

- Further independent protocol/security review of `internal/dtls13` and
  `internal/xio/dtlsopen`, including RFC 9846 §1.2.
- Spare-CID issuance/replenishment interop when a reference peer supports it.
  Local renewal is implemented; this interop gap is not a merge blocker.
- wolfSSL still requires an unfragmented first ClientHello, so PQ at
  1200/512/256 times out. Add independent Pion PQ coverage at those MTUs.
- OpenSSL cookie-listener fragmentation (`SSL_new_listener` /
  `demos/dtlslistenerecho`) remains untested.
- PMTU: routed Windows/macOS validation awaits suitable test environments.
  Possible improvements: RTT-based probe spacing, safe discovery on shared
  listeners, and OS PMTU hints without connecting the active migration socket.
  `raiseTimer` is 600s (`TestProbeTimeoutMeetsRFC8899`); no remaining test
  drives that periodic raise through a path-MTU change.
- Optional lab-only BoringSSL packet-BIO adapter; keep it out of `make check`.
- Recheck official OpenSSL/socat releases when 4.1 is usable. Do not patch the
  parity baseline to obtain a test peer.
- On Go upgrades, recheck `defaultCipherSuites` and `defaultGroups` against
  crypto/tls, and the TLS ML-DSA mapping when its RFC is published.

Do not: relax certificate checks; add DTLS 1.2 or browser workarounds; raise
production MTU or drop PQ defaults to paper over peer gaps; delay CID requests
until movement; invent a second cookie path; treat `Listener.receive` as having
concurrent admission callers (it has one). After a verified Finished, abandon
the previous same-address association (RFC 9147 §5.11) with no CID exemption.
Immediate CID rotation must update pending path probes.

## Validation

Ordinary `make check` does not download lab tools. Linux/macOS/Windows tests,
including race, cover the implementation. Classic `OPENSSL_DTLS_TO_SERVER`,
`OPENSSL_DTLS_TO_CLIENT` and `RCVTIMEO_DTLS` pass; cases that pin DTLS 1.2
remain unsupported. See the [scorecard](../testdata/scorecard/README.md#dtls-13).

RFC 9147 §4.5.2/§11 invalid-record paths are classified: unauthenticated
datagrams are dropped; authenticated inner/handshake/alert violations abort.
Malformed ACK bodies are discarded (RFC 9147 §4.5.2), including OpenSSL
lists whose declared length exceeds the decrypted body. Disrupted handshake
flights (holes or out-of-order messages) are ACKed; a quiet in-order prefix
is ACKed after 1/4 of the retransmit interval (RFC 9147 §7.1). An in-order
flight that we answer immediately is not ACKed until the local Finished is
on the wire. Queued ACK record numbers are capped so unauthenticated
cookie-cache traffic cannot exceed the hello-entry budget. New-byte flight
bursts do not consume retransmission retries.

In-process loss/reorder with mutual ML-DSA-44/65/87 succeeds at MTU 256
with X25519MLKEM768 (`TestPostQuantumHandshakeLoss`). Independent OpenSSL
`s_server`/`s_client` coverage at 1200/512/256 is ChaCha20-Poly1305 plus
X25519MLKEM768 (ECDSA and mutual ML-DSA-44/65/87); a dropped first
ClientHello is ML-DSA-44 against `s_server`
(`TestInteropOpenSSLServerSmallMTUPQHandshakeLoss`). Those results do not
cover SecP256r1MLKEM768 or SecP384r1MLKEM1024. Large ML-DSA flights at 256
still take several retransmission intervals because peers often do not ACK
fragments before the next 10-record burst.

Current PMTU tests are in-process discovery (`internal/dtls13/pmtu_*.go`)
and Linux loopback `PMTUDISC_PROBE` (`pmtu_df_linux_test.go`). Privileged
CI runs `./internal/xio/privileged` and has no DTLS PMTU cases. Historical
Linux routed IPv4/IPv6 1500→1280→1500 results are not in this tree.

On Linux, build the pinned peers and run interop:

```sh
sudo apt-get install --no-install-recommends cmake ninja-build
python3 scripts/dtls13-lab.py
SOCAT_DTLS13_TOOLS="$HOME/socat-dtls13-lab/tools.json" \
  go test -tags dtlsinterop ./internal/dtls13 -run TestInterop -v
```

The lab lives under `~/socat-dtls13-lab/`. `--only classic` attempts the
separate classic/OpenSSL build.
