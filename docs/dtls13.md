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
`defaultCipherSuites`, `defaultGroups`, and `signatureAlgorithms`. See
[Default settings](#default-settings). The TLS ML-DSA mapping follows
`draft-ietf-tls-mldsa-05`. New algorithms still need DTLS wire integration.

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
  Cookie HMAC secrets rotate every 60 seconds and keep one previous key.
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

Last interoperability runs: 2026-09-08 (pinned matrices, master `cfd5566`) and
2026-09-09 (default-settings table and empty-key-share ClientHello captures).
Pins are in
[dtls13-baseline.json](../scripts/dtls13-baseline.json) and
[dtls13-lab.py](../scripts/dtls13-lab.py). Limits are for those revisions.

The three record cipher suites in the pinned matrices are **AES-128-GCM,
AES-256-GCM, and ChaCha20-Poly1305**. Those tests select each suite and group
explicitly, regardless of hardware preference. 21 combinations means three
suites × seven groups. Default-settings tests do not pin suites or groups.

Collect the default-settings rows on the Linux lab with:

```sh
SOCAT_DTLS13_TOOLS=/path/to/tools.json go test -v -tags dtlsinterop ./internal/dtls13 -run '^TestDefaultSettings' -count=1
```

Each case reads the negotiated cipher, group and peer certificate from our
connection state after a verified handshake, then checks the echo. Raw peer
output is retained on success and failure; OpenSSL's `-brief` summary shows its
view of the connection and the certificate we presented. Errors fail that row
and include the peer's exit status; the other rows still run. The command returns
nonzero when any exchange fails, including the peer limitations documented below.
These lab measurements are excluded from ordinary `make check`.

### Default settings

Library `Config` zeros (`prepareConfig`) used by `TestDefaultSettings*`:

| Knob | Default |
| --- | --- |
| MTU | 1200 |
| Connection ID length | 8; CID and RFC 9853 RRC offered (`DisableMigration` false) |
| Handshake timeout | 30s; 256 listener associations |
| `UnfragmentedProbes` | off for `Client`/`Listen`. Command-line clients still default it on for eligible dedicated sockets. |
| Cipher suites | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 when AES-GCM hardware is present; ChaCha first otherwise |
| Groups | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256, P-384, P-521. The first ClientHello sends the preferred share plus an X25519 fallback when they fit one handshake fragment. Otherwise it sends an empty `key_share` list and HelloRetryRequest supplies the selected group. Other groups already use HelloRetryRequest. |
| `signature_algorithms` | ML-DSA-44, ML-DSA-65, ML-DSA-87, then RSA-PSS SHA-256, ECDSA P-256, Ed25519, RSA-PSS SHA-384/512, ECDSA P-384/P-521 |

Cookies are always required. The ECDSA P-256 and ML-DSA-65 rows use one
certificate type on both ends. The third row is two CAs and two leaves:

- ML-DSA CA signs the ML-DSA-65 leaf.
- ECDSA CA signs the ECDSA P-256 leaf.

`Config.Certificates` lists ML-DSA-65 first, then ECDSA P-256. Verifiers
trust both CAs, so either leaf verifies. OpenSSL loads that trust store with
`-CApath` (hashed directory from `openssl rehash`) and `-CAfile` (concatenated
PEMs; `s_server` still reads CertificateRequest CA names from `-CAfile`).
`s_server` also gets both leaves (`-cert` ML-DSA-65, `-dcert` ECDSA P-256).
`s_client` has no second-cert flag, so it presents the ECDSA leaf. Pion and
wolfSSL cannot parse ML-DSA, so they get the ECDSA leaf and ECDSA CA only;
we still trust both CAs and fall back to ECDSA because those peers do not
offer ML-DSA.

Peer CLIs still need a DTLS 1.3 version switch (`s_client`/`s_server
-dtls1_3`, wolfSSL `-v 4`). That is not a suite or group pin. The tests omit
`-groups`, `-ciphersuites`, `-mtu`, `--pqc`, `--force-curve`, `-l`, `-group`,
`-cipher`, and `-migrate=false`.

OpenSSL 4.1 (`82733d9`) defaults that affect this table:

- Groups (`TLS_DEFAULT_GROUP_LIST`): X25519MLKEM768, SecP256r1MLKEM768,
  curveSM2MLKEM768; then X25519, P-256; X448, P-384, P-521; curveSM2;
  ffdhe2048, ffdhe3072. Unavailable groups are skipped. X25519MLKEM768 and
  X25519 have initial key shares. SecP384r1MLKEM1024 is absent.
- TLS 1.3 ciphers (`openssl ciphers -tls1_3 -s`): AES-256-GCM, ChaCha20-Poly1305,
  AES-128-GCM.
- `signature_algorithms`: ML-DSA-65, ML-DSA-87, ML-DSA-44, then ECDSA/EdDSA/RSA
  ([openssl/openssl#26975](https://github.com/openssl/openssl/pull/26975)).
  We advertise ML-DSA-44 first. A single ML-DSA-65 certificate still selects
  ML-DSA-65.

Pion (`59f4c33`) library defaults: MTU 1200; groups X25519MLKEM768, X25519,
P-256, P-384; TLS 1.3 ciphers AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305;
ECDSA/Ed25519/RSA signatures only (no ML-DSA). The lab oracle leaves
`-migrate` true, so CID and RRC are offered. After the handshake we send
`RequestConnectionID`. Pion's public endpoints reject that with
`unexpected_message`. The application echo can finish first, so those rows
often fail after a verified handshake rather than always failing.

wolfSSL (`d72f6d9`) example binaries in the lab cmake build have DTLS 1.3 and
CID but cannot load ML-DSA certificates. Their client advertises
X25519MLKEM768 without `--pqc`, but initially sends a P-256 key share in a
263-byte ClientHello. Our HelloRetryRequest requests X25519MLKEM768 and
supplies a cookie. The cookie-bearing retry spans 1400-byte and 158-byte
datagrams at their compile-time send MTU of 1400; our listener accepts it.
In the opposite direction, a hybrid key share is 1216 bytes and would
fragment at MTU 1200. The first ClientHello therefore omits `key_share` and
fits in one 151-byte datagram. wolfSSL HelloRetryRequests a cookie and a
group; the cookie-bearing retry may fragment and is accepted. Default
settings omit `--pqc`, so their server selected P-256 and AES-256-GCM.
With `--pqc X25519MLKEM768` it selected X25519MLKEM768 (cookie length 69
on the retry).

On this AES-NI host OpenSSL and Pion still negotiated **AES-128-GCM /
X25519MLKEM768**. OpenSSL `s_server` HelloRetryRequests the missing hybrid
share (no cookie in that capture), which is one extra round trip compared
with an X25519 ClientHello that already carries a share. When we are the
server we pick AES-128-GCM from the intersection. wolfSSL as client still
completes AES-128-GCM / X25519MLKEM768.

| Peer | Certificate | Ours as client | Ours as server |
| --- | --- | --- | --- |
| OpenSSL `82733d9` | ECDSA P-256 | pass: AES-128-GCM / X25519MLKEM768 | pass: AES-128-GCM / X25519MLKEM768 |
| OpenSSL `82733d9` | ML-DSA-65 | pass: AES-128-GCM / X25519MLKEM768 | pass: AES-128-GCM / X25519MLKEM768 |
| OpenSSL `82733d9` | ML-DSA-65, then ECDSA P-256 | pass: AES-128-GCM / X25519MLKEM768; peer selected ML-DSA-65 | pass: AES-128-GCM / X25519MLKEM768; we selected ML-DSA-65 |
| wolfSSL `d72f6d9` | ECDSA P-256 | pass: AES-256-GCM / P-256 (no `--pqc`) | pass: AES-128-GCM / X25519MLKEM768 |
| wolfSSL `d72f6d9` | ML-DSA-65 | fail: example server cannot load the cert | fail: example client cannot load the cert |
| wolfSSL `d72f6d9` | ML-DSA-65, then ECDSA P-256 | pass: AES-256-GCM / P-256 (no `--pqc`); ECDSA fallback | pass: AES-128-GCM / X25519MLKEM768; ECDSA fallback |
| Pion `59f4c33` | ECDSA P-256 | handshake AES-128-GCM / X25519MLKEM768, then often fail: `unexpected message` (CID) | handshake AES-128-GCM / X25519MLKEM768, then often fail: `unexpected message` (CID) |
| Pion `59f4c33` | ML-DSA-65 | fail: `invalid private key type` | fail: `invalid private key type` |
| Pion `59f4c33` | ML-DSA-65, then ECDSA P-256 | ECDSA fallback; same CID result as the ECDSA row | ECDSA fallback; same CID result as the ECDSA row |
| BoringSSL `4a92579` | ECDSA P-256 | n/a: no packet-BIO interop | n/a |
| BoringSSL `4a92579` | ML-DSA-65 | n/a | n/a |
| BoringSSL `4a92579` | ML-DSA-65, then ECDSA P-256 | n/a | n/a |

### Pinned-matrix coverage

These cases pin cipher suite and group (and, for Pion public APIs, disable
CID). They are not the default-settings table.

**OpenSSL 4.1 (`82733d9`)** — pass: 21 suite×group combinations, our client at
MTU 4096 (`TestInteropOpenSSLServer`) and our listener at MTU 1200
(`TestInteropOpenSSLClient`); all three suites with mutual ML-DSA-44/65/87 at
4096; X25519MLKEM768 at 1200/512/256 with ECDSA and mutual ML-DSA-44/65/87 in
both roles; dropped first ClientHello for ML-DSA-44 against `s_server` at
those MTUs; `SSL_new_listener` cookie path (`TestInteropOpenSSLCookieListener`,
`TestInteropOpenSSLCookieListenerHandshakeLoss`) with all three suites, our
client, mutual ECDSA, X25519 at 1200 and X25519MLKEM768 at 1200/512/256,
including a dropped first ClientHello fragment and a dropped
HelloRetryRequest. Captured UDP payloads stayed within the configured MTU
(cookie-path sent maxima 1191/503/256). Limits: no DTLS 1.3 CID; `SSL_set_mtu`
is not usable on the listener object (datagrams of at most 228 bytes after
accept on that path); OpenSSL may emit ACK lists larger than the MTU
(malformed ACK bodies are discarded); NIST hybrids were not run at
1200/512/256.

**wolfSSL (`d72f6d9`)** — pass: 21 suite×group combinations, our client at MTU
4096; 12 mutual-auth CID cases in both roles at MTU 1200 (all suites, P-256,
request ACKs, rotation with lost ACKs and KeyUpdate); X25519MLKEM768 with
AES-128-GCM, `--pqc`, empty first ClientHello, cookie HelloRetryRequest, and
echo at 1200/512/256 (retry fragments 2/3/7). Limits: still rejects a
fragmented unverified first ClientHello; no spare issuance/replenishment or
RFC 9853 RRC. The lab build enlarges the extra read buffer to 4096 bytes for
hybrid offers.

**Pion (`59f4c33`)** — pass: mutual authentication, bidirectional KeyUpdate and
rebinding/RRC in both roles through protocol drivers using initial CIDs;
public `Client`/`Listen` with CID/RRC disabled: X25519MLKEM768 × all three
suites, ECDSA mTLS, both roles at 1200/512/256 including a dropped first
ClientHello (`TestInteropPionSmallMTUPQ`,
`TestInteropPionSmallMTUPQHandshakeLoss`). Limits: rejects CID-management
messages, so migration-enabled public endpoints do not fully interoperate;
may emit datagrams above the configured MTU (observed 1225/537/290); NIST
hybrids and ML-DSA were not run against Pion.

**BoringSSL (`4a92579`)** — test shim builds only. Packet-BIO adapter and
interop tests are not written. Lower priority; lab-only.

OpenSSL `s_server` accepted our fragmented X25519MLKEM768 ClientHello at 256
with ECDSA and mutual ML-DSA echo. With an empty first `key_share` it
HelloRetryRequests X25519MLKEM768 and completes echo at 1200/512/256
(AES-128-GCM, ECDSA). An X25519 ClientHello that already carries a share
still completes without that extra round trip.

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
- wolfSSL still rejects a fragmented unverified first ClientHello. Our
  client now omits oversized initial key shares so that flight stays in one
  datagram; default-settings wolfSSL without `--pqc` then selects P-256.
  Independent Pion public-API coverage at 1200/512/256 is X25519MLKEM768
  with all three record cipher suites and CID disabled. Migration-enabled
  Pion public endpoints still often fail after handshake on
  `RequestConnectionID`.
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
`s_server`/`s_client` coverage at 1200/512/256 uses all three record cipher
suites with X25519MLKEM768 (ECDSA and mutual ML-DSA-44/65/87); a dropped
first ClientHello is ML-DSA-44 with each suite against `s_server`
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
  go test -tags dtlsinterop ./internal/dtls13 -run 'TestInterop|TestDefaultSettings' -v
```

The lab lives under `~/socat-dtls13-lab/`. `--only classic` attempts the
separate classic/OpenSSL build.
