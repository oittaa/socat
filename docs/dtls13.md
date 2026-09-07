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
  immediate rotation. Low-spare requests run automatically, but consuming a
  spare does not retire older CIDs. A full issuance pool returns empty until
  explicit immediate rotation.
- Not implemented: DTLS 1.0/1.2, PSK, resumption, 0-RTT, post-handshake
  client authentication. `EXEC,nofork` cannot use DTLS.

## Independent peers

Checked 2026-09-05. Pins are in
[dtls13-baseline.json](../scripts/dtls13-baseline.json) and
[dtls13-lab.py](../scripts/dtls13-lab.py). Limits are for those revisions.

| Peer | Passing coverage | Limits |
| --- | --- | --- |
| OpenSSL 4.1 snapshot (`82733d9`) | Both roles; 21 suite/group combinations; mutual ML-DSA-44/65/87. | No DTLS 1.3 CID. Partial-flight ACK handling blocks the tested small-MTU PQ exchanges. |
| wolfSSL master (`d72f6d9`) | 21 suite/group combinations with our client. 12 mutual-auth CID cases in both roles (MTU 1200, all suites, P-256, request ACKs, rotation with lost ACKs and KeyUpdate). | No spare issuance/replenishment or RFC 9853 RRC. |
| Pion (`59f4c33`) | Mutual authentication, bidirectional KeyUpdate and rebinding/RRC in both roles through protocol drivers using initial CIDs. | Rejects CID-management messages. Migration-enabled public endpoints request spares and do not fully interoperate. |
| BoringSSL (`4a92579`) | Test shim builds. | Packet-BIO adapter and interop tests are not written. |

Algorithm tests use 4096-byte loopback MTUs where needed; the wolfSSL lab
build also enlarges its extra read buffer to 4096 bytes for hybrid offers.
These passes do not establish PQ interoperability at production MTUs.

None of the pinned peers supplies independent spare-CID issuance coverage.
System OpenSSL 3.5.5 is DTLS 1.2 only. Unmodified classic socat 1.8.1.3 cannot
build against the pinned OpenSSL 4.1 headers. Keep lab builds separate from
system libraries and the [classic parity baseline](../scripts/classic-baseline.json).

## Remaining work

- Independent protocol/security review of `internal/dtls13` and
  `internal/xio/dtlsopen`, including RFC 9846 §1.2.
- Spare-CID issuance/replenishment interop, pinned to a peer that supports it.
- Sustained CID pool renewal when consumed identifiers remain in the issuer pool.
- Independent PQ tests at MTU 1200/256/512 with loss, reorder and mutual ML-DSA.
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
