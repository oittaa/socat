# DTLS 1.3

User options and examples are in the [README](../README.md#dtls-13).
RFCs and code map: [dtls13-standards.md](dtls13-standards.md).
BCP 14 matrix vs OpenSSL, wolfSSL, and Pion: [dtls13-compliance.md](dtls13-compliance.md).

Certificate-authenticated DTLS 1.3 over UDP on Linux, macOS and Windows:
cookies, SNI/ALPN, mutual authentication, fragmentation, selective ACKs,
retransmissions, replay protection, key updates, CID rotation and RFC 9853
enhanced path validation. Endpoints reuse the existing credentials, socket
options, peer filters, fork lifecycle, deadlines and cancellation.

Algorithm defaults match Go 1.27's TLS 1.3 set: AES-128/256-GCM and
ChaCha20-Poly1305; X25519, P-256/P-384/P-521, X25519MLKEM768,
SecP256r1MLKEM768 and SecP384r1MLKEM1024; RSA-PSS, ECDSA, Ed25519 and
ML-DSA-44/65/87. The TLS ML-DSA mapping follows `draft-ietf-tls-mldsa-05`.
`TestGoTLS13AlgorithmDefaults` detects default-set drift. New algorithms still
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

## Independent peers

Checked 2026-09-07. Pins are in
[dtls13-baseline.json](../scripts/dtls13-baseline.json) and
[dtls13-lab.py](../scripts/dtls13-lab.py). Limits are for those revisions.

| Peer | Passing coverage | Limits |
| --- | --- | --- |
| OpenSSL 4.1 snapshot (`82733d9`) | Both roles; 21 suite/group combinations; mutual ML-DSA-44/65/87 at MTU 4096. Our client → `s_server` with X25519MLKEM768 and ECDSA, including echo, at MTU 1200/512/256. | No DTLS 1.3 CID. `s_client` does not ACK our large server flights: mutual ML-DSA as OpenSSL client fails at MTU 1200; ECDSA as OpenSSL client fails at 256. Our client ML-DSA handshake can return at 256, but echo is not reliable. Cookie-listener first-fragment behavior was not retested. |
| wolfSSL master (`d72f6d9`) | 21 suite/group combinations with our client at MTU 4096. Classical X25519 and P-256 with our client at 1200/512/256. 12 mutual-auth CID cases in both roles (MTU 1200, all suites, P-256, request ACKs, rotation with lost ACKs and KeyUpdate). | Rejects a fragmented unverified first ClientHello, so PQ at 1200/512/256 times out. No spare issuance/replenishment or RFC 9853 RRC. |
| Pion (`59f4c33`) | Mutual authentication, bidirectional KeyUpdate and rebinding/RRC in both roles through protocol drivers using initial CIDs. | Rejects CID-management messages. Migration-enabled public endpoints request spares and do not fully interoperate. Production-MTU PQ was not independently proven. |
| BoringSSL (`4a92579`) | Test shim builds. | Packet-BIO adapter and interop tests are not written. Lower priority; lab-only. |

The wolfSSL lab build enlarges its extra read buffer to 4096 bytes for hybrid
offers and still requires an unfragmented first ClientHello. OpenSSL `s_server`
accepted our fragmented PQ ClientHello at 256 with ECDSA echo; keep mutual
ML-DSA echo checks at 4096. In-process loss/reorder with mutual ML-DSA-44/65/87
succeeds at 1200/512/256 (`TestPostQuantumHandshakeLoss` and the 2026-09-07
recheck). These in-process checks do not establish independent peer interop
under loss/reorder.

None of the pinned peers supplies independent spare-CID issuance coverage.
System OpenSSL 3.5.5 is DTLS 1.2 only (`s_client` has no `-dtls1_3`). OpenSSL
4.1 is still unreleased (planned October 2026); 4.0 has no DTLS 1.3.
Unmodified classic socat 1.8.1.3 (`12c08bf`) fails to compile against the
pinned OpenSSL 4.1 headers (`ASN1_OCTET_STRING` is an incomplete type in
`xio-openssl.c`). Keep lab builds separate from system libraries and the
[classic parity baseline](../scripts/classic-baseline.json). The TLS ML-DSA
mapping is still `draft-ietf-tls-mldsa-05` (IESG approved, RFC not published);
Go 1.27.1 defaults matched `TestGoTLS13AlgorithmDefaults`.

## Remaining work

- Independent protocol/security review of `internal/dtls13` and
  `internal/xio/dtlsopen`, including RFC 9846 §1.2. RFC 9147 §4.5.2/§11
  invalid-record paths are classified: unauthenticated datagrams are dropped;
  authenticated inner/handshake violations still abort.
- Spare-CID issuance/replenishment interop, pinned to a peer that supports it.
- Remaining production-MTU PQ gaps: wolfSSL unverified CH0 must be unfragmented;
  OpenSSL `s_client` ACK of large server flights; Pion PQ at 1200/512/256.
- Diagnose our-client mutual ML-DSA echo failures at small MTUs; the cause
  is not yet isolated.
- Independent PQ tests at MTU 1200/512/256 with controlled loss/reorder and
  mutual ML-DSA; successful loopback exchanges do not cover this.
- PMTU: [investigation](dtls13-pmtu.md); default 1200 is below Ethernet; do not set DF on shared listeners.
- Lab-only BoringSSL packet-BIO adapter; keep it out of `make check`.
- Recheck official OpenSSL/socat releases when 4.1 is usable. Do not patch the
  parity baseline to obtain a test peer.
- On Go upgrades, investigate `TestGoTLS13AlgorithmDefaults` drift and recheck
  the TLS ML-DSA mapping when its RFC is published.

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

On Linux, build the pinned peers and run interop:

```sh
sudo apt-get install --no-install-recommends cmake ninja-build
python3 scripts/dtls13-lab.py
SOCAT_DTLS13_TOOLS="$HOME/socat-dtls13-lab/tools.json" \
  go test -tags dtlsinterop ./internal/dtls13 -run TestInterop -v
```

The lab lives under `~/socat-dtls13-lab/`. `--only classic` attempts the
separate classic/OpenSSL build.
