# DTLS 1.3 implementation

Status: draft; default stream/file-transfer sizing and independent protocol
review remain merge blockers. Independent spare-CID issuance/replenishment
testing is a follow-up when reference peers support it, not a merge blocker.
RFC-based review and local regression coverage remain required. Algorithm
support and scoped validation are described below.

Before fixing protocol or endpoint behavior, read the applicable references
and contract notes in [the standards guide](dtls13-standards.md).

Implemented foundations: AES/ChaCha20 record protection and header masking, replay
windows, bounded hello/certificate codecs, handshake reassembly, selective ACKs,
ten-record flight bursts, timer backoff, and client/server certificate handshakes
with cookies, SNI, ALPN, and optional mutual authentication. A record-driven
session completes independent handshakes and exchanges application datagrams.
Key updates, CID rotation, and RFC 9853 enhanced path validation are implemented.
The UDP connection/listener API passes datagram, deadline, cancellation,
half-close, key-update, CID-rotation, and real UDP rebinding tests. Registered
endpoints preserve certificate options, datagram boundaries, and accepted
associations after a forked listener reaches its accept timeout.

## Scope

Implement DTLS 1.3 over UDP on Linux, macOS, and Windows, preferring Go's
standard library and allowing `golang.org/x/` packages. Reuse the existing endpoint
and credential infrastructure. Do not implement DTLS 1.0 or 1.2, stream TLS
fallback, SCTP, or a WebRTC/ICE/SRTP stack.

The certificate-based profile includes AES-128-GCM/SHA-256,
AES-256-GCM/SHA-384, ChaCha20-Poly1305/SHA-256, P-256/P-384/P-521, X25519,
the three RFC 10024 ML-KEM hybrids, RSA/ECDSA/Ed25519/ML-DSA authentication, client
certificates, SNI, ALPN, HelloRetryRequest/cookies, handshake fragmentation,
retransmissions/ACKs, replay protection, key updates, cancellation, and bounded
resource usage. Optional PSKs, resumption, early data, and post-handshake client
authentication are deferred. Unsupported optional features must not be
advertised; valid offers must be processed according to the RFC.

The user selected connection IDs and address migration for the first merge.
Implement RFC 9853 path validation, amplification limits, CID rotation, and
bounded migration state. Fixed-peer mode must not negotiate connection IDs.

The current listener admits at most 16 concurrent handshakes and defaults to
256 associations. It uses a stateful cookie exchange bound to the original
peer address, limits pre-cookie responses to three times received bytes,
caps queued encrypted packets at 8 MiB per listener and reassembly reservations
at 16 MiB, and applies the configured handshake deadline. Each association has
ten queued encrypted datagrams and sixteen queued application datagrams;
overflow is dropped, as with a UDP receive buffer. CID pools are bounded to
eight identifiers, plus one temporary identifier during immediate rotation.
CID/RRC address changes must pass the listener's peer-address filter.

An acknowledged handshake releases its master secret, transcript, and the
client/server handshake-handler closures. Old traffic keys retained for
retransmissions are managed independently. Concurrent association isolation,
resource accounting on cancellation, read/write deadline changes, datagram
truncation, and half-close are tested through the connection API.

Current resource bounds include 1 MiB per handshake message, 16 pending message
sequences, 2 MiB of reassembled message bodies per association, 64 certificates,
and Go's 8192-bit RSA verification work limit. RSA minimum sizes follow Go
and the selected PSS encoding, without a separate local 2048-bit floor.
Connection-level admission and lifetime
limits must bound aggregate memory before endpoint registration.

## Algorithm policy

Central registries describe supported suites, groups, and CertificateVerify
schemes. Defaults currently match Go 1.27's TLS 1.3 algorithm set; group and
signature preference order is checked against an actual Go ClientHello in
`TestGoTLS13AlgorithmDefaults`. Cipher preference favors ChaCha20 when local
AES-GCM acceleration is unavailable. Explicit configuration may restrict the
implemented suites or groups without an arbitrary list-length cap.

Go supplies ECDH, ML-KEM, ML-DSA, signing, and X.509 parsing/verification.
`crypto.SignMessage` also supports opaque message-signing keys.
`golang.org/x/crypto` supplies ChaCha20-Poly1305 and its record-number mask;
`golang.org/x/sys/cpu` supplies hardware capabilities. No new module version
is required. DTLS retains protocol checks for offered schemes, matching
ECDSA curves/ML-DSA parameters, RSA-PSS encoding, hybrid wire lengths and
component order, and cipher-specific key-usage limits.

The hybrids are X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024.
ML-DSA-44/65/87 CertificateVerify follows `draft-ietf-tls-mldsa-05`; this TLS
signature specification remains a draft. RFC 9954 describes hybrid design;
RFC 10024 defines these hybrid key exchanges. All seven default groups, all
three suites, and all ten TLS 1.3 signature schemes are implemented.

Primitive fixes and certificate-policy improvements flow through Go directly.
An entirely new group, signature scheme, or AEAD still needs a DTLS wire
mapping and interoperability tests. The Go-default probe fails CI when the
advertised set or checked preference order changes; it does not dynamically
enable unimplemented algorithms or mirror every Go `GODEBUG`/FIPS profile.

## Sources and compatibility baseline

- [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.txt) defines the DTLS
  changes to the TLS 1.3 protocol originally specified in RFC 8446.
  [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.txt) now replaces RFC 8446;
  its section 1.2 changes remain an explicit review target, not a completed
  compliance claim. Apply the DTLS-specific rules and verified errata.
  [RFC 9853](https://www.rfc-editor.org/rfc/rfc9853.txt) specifies return
  routability with connection IDs. The [standards guide](dtls13-standards.md)
  maps these and the hybrid/signature references to relevant code.
- Official classic source: https://repo.or.cz/socat.git.
  Release `tag-1.8.1.3`: `12c08bf66d709fba17035ce95d85bd218428d9ba`.
  Master: `af5388c898c7bb60997935aee93c223deba60c4a`.
  Verified against the official remote on 2026-09-05: release and master
  trees are identical. Read `doc/socat.yo` from both revisions, including
  `OPENSSL-DTLS-CLIENT` and `OPENSSL-DTLS-SERVER`.
- Preserve documented endpoint aliases, verification defaults, socket options,
  datagram boundaries, and lifecycle behavior. The user's explicit 1.3-only
  requirement permits rejecting older protocol versions; document that limit.
- Classic's generic `DTLS_client_method`/`DTLS_server_method` may negotiate 1.3
  with a suitable OpenSSL, but its version-option parser lacks `DTLS1.3`.
  Test negotiated versions directly. A successful handshake without a verified
  version is not evidence of DTLS 1.3 interoperability.
- The lab's system OpenSSL is 3.5.5 and supports DTLS only through 1.2.
  OpenSSL added 1.3 to master in August 2026 for the planned 4.1 release.
  Keep development builds separate from system OpenSSL and pinned classic
  parity worktrees.

## Pion reuse

Audited reference: Pion DTLS
`59f4c33b90c58fa6256a9cf1db49d1a9976b3536` (MIT).
Preserve upstream copyright/license notices and record each adapted file.
Adapt small, relevant components and test vectors; do not import the full
DTLS 1.2/1.3 state framework or its logging/transport dependencies.

Pion's main branch is still completing DTLS 1.3. Open upstream issues include
expanded interoperability coverage (#1044), remaining implementation gaps
(#1000), and PSK completion (#972). Copied code needs review against the RFC
and independent implementations. Pion interoperability alone cannot detect
bugs shared with copied Pion code.

Do not classify valid fragmentation, overlap, loss/reordering, unknown
extensions, or HelloRetryRequest as browser workarounds. Omit compatibility
branches only when their purpose and relevance are established. Record any
necessary current-peer deviation with the affected version, RFC section, and
focused regression test.

## Validation and lab

`scripts/dtls13-baseline.json` pins source revisions for reproducibility.
The opt-in `scripts/dtls13-lab.py` builds wolfSSL's pinned master, BoringSSL's test shim,
Pion's helper, and OpenSSL's 4.1 development snapshot. `--only classic` also attempts a separate
classic socat build against that OpenSSL. It does not install system libraries, change classic parity baselines,
or run during ordinary `make check`.

On the Linux lab, install the build prerequisites if absent:

```sh
sudo apt-get install --no-install-recommends cmake ninja-build
python3 scripts/dtls13-lab.py
```

Source checkouts, builds, logs, and tool paths remain under
`~/socat-dtls13-lab/`; `tools.json` records exact revisions and paths. These
external tools are test references, not dependencies of the socat executable.

Verified on 2026-09-05: OpenSSL and wolfSSL completed a DTLS 1.3 handshake
with certificate verification and echoed an application datagram. BoringSSL's
shim built successfully; its interoperability adapter remains to be implemented.
Unmodified classic 1.8.1.3 does not build against the pinned OpenSSL 4.1 headers:
its certificate handling accesses the now-opaque `ASN1_OCTET_STRING` fields.
It is therefore not a verified DTLS 1.3 oracle. Keep its source unmodified and
use the independent DTLS implementations for protocol validation.

Our client completed mutually authenticated handshakes and echoed datagrams
against wolfSSL and OpenSSL with all 21 cipher/group combinations. Our server
completed the same checks against the OpenSSL client. All three ML-DSA
parameter sets also completed mutually authenticated exchanges with OpenSSL
in both directions, using X25519MLKEM768 and ChaCha20-Poly1305.
The wolfSSL exchanges also require key updates in both directions before
accepting the echoed data. These references did not negotiate CID/RRC in those
exchanges. A separate pinned Pion helper negotiated CID/RRC, completed mutual
certificate authentication and bidirectional key updates, and echoed data after
the client closed its UDP socket and rebound to a new port. Pion performed the
RRC challenge in that test. A second Pion client test validates our enhanced
old-path/new-path procedure after the client replaces its UDP socket.

The pinned Pion post-handshake dispatcher implements only KeyUpdate and
NewSessionTicket; it sends an unexpected_message alert for a valid
RequestConnectionID despite having negotiated CIDs. The Pion protocol-driver
tests therefore exercise RRC using the initial CIDs without requesting spares.
Our connection API proactively requests spare CIDs, so migration-enabled
endpoints do not fully interoperate with this incomplete Pion snapshot.
No peer-specific relaxation is added; `dtls-migration=0` is available for
fixed-address use. CID rotation/request/replenishment is verified between our
peers with loss and reordering. The wolfSSL checks below independently cover
request acknowledgement and immediate rotation; spare issuance and
replenishment still lack an independent reference.

The pinned OpenSSL snapshot documents that it has no DTLS 1.3 CID support in
[its DTLS guide](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/doc/man7/ossl-guide-dtlsv13.pod).
Thus none of these pinned OpenSSL, wolfSSL or Pion references supplies an
independent spare-issuance/replenishment test peer. This unavailable coverage
is not a merge blocker. RFC-based CID review, deterministic local tests and
fixing defects they reveal remain merge requirements. When upstream support
arrives, pin it and add both-role replenishment tests with loss, reordering
and key updates. This is a limitation of the recorded revisions, not a claim
about every implementation or future release. See item 2 of
[the follow-up plan](dtls13-follow-up.txt) for the acceptance criteria.

On 2026-09-05, wolfSSL master
`d72f6d9e4e85ffcadfa0c737959dc26b8717947a` passed twelve additional CID cases
through our public connection/listener API under the race detector. These
use P-256, mutual certificate authentication, the default 1200-byte MTU,
all three ciphers, and both client/server roles. Each association acknowledges
our proactive RequestConnectionID, completes two immediate CID rotations
interleaved with bidirectional key updates, and exchanges application data.
Six cases deliberately drop the first datagram using each replacement CID
(wolfSSL's rotation ACK); retransmission completes both rotations and retires
the previous CID. Our production protocol code is unchanged.

The receive-side implementation was merged in
[wolfSSL PR #10626](https://github.com/wolfSSL/wolfssl/pull/10626) on 2026-07-03.
It parses and acknowledges RequestConnectionID without issuing a response,
accepts immediate NewConnectionID updates, and discards spare CID offers.
It does not negotiate RFC 9853 return routability. These results do not verify
spare issuance/replenishment or address migration against wolfSSL.
The latest release, `v5.9.2-stable`
(`ac01707f552c611fbd135cc723b2682b3e7f80f2`), predates that change: both roles
negotiate static CIDs but fail the same post-handshake test with
unexpected_message. The reference pin was advanced to master for reproducible
CID coverage; the 21 wolfSSL cipher/group checks were rerun against it.

The algorithm interop tests use a 4096-byte local MTU for our client, and for
both peers when testing OpenSSL as server or using ML-DSA. These are loopback
algorithm checks, not evidence of loss recovery at the default 1200-byte MTU.
The wolfSSL lab build enables X25519 and increases its additional DTLS read
buffer to 4096 bytes. Its default receive buffer truncated the 1909-byte
cookie-bearing SecP384r1MLKEM1024 ClientHello with AES-256-GCM; debug logs
reported partial records and dropped them.
The previously tested wolfSSL 5.9.2 stateless server drops fragmented initial ClientHellos;
hybrid offers at MTU 1200 timed out. The pinned OpenSSL snapshot does not
acknowledge partial server flights (`dtls_msg_needs_ack` excludes them), and
its server can reject handshake ACKs with unexpected_message. At MTU 512,
large ML-DSA server flights therefore stalled; hybrid client handshakes also
failed against that server. No runtime peer exception or larger default MTU
is introduced. Independent small-MTU/loss coverage for these algorithms
remains outstanding. Local ML-DSA mutual-authentication tests use 256-byte
datagrams with dropped/reordered flights and final ACK loss.

The receive queue holds one recommended ten-record handshake transmission
while ML-DSA certificate verification runs. The four-record queue could drop
part of an otherwise intact flight under the race detector; listener byte
budgets continue to cap aggregate buffering.

The Pion helper is built inside the isolated reference checkout; its imports
are not dependencies of socat's module. The opt-in tests
require an explicit manifest and never download dependencies:

```sh
SOCAT_DTLS13_TOOLS="$HOME/socat-dtls13-lab/tools.json" \
  go test -tags dtlsinterop ./internal/dtls13 -run TestInterop -v
```

Acceptance requires both client/server directions against independent peers,
verified 1.3 negotiation, certificate success/failure cases, AEAD suites and
key-exchange groups, loss/duplication/reordering/fragment overlap, final ACK
loss, key updates with loss, concurrent listener sessions, deadlines, resource
limits, and malformed-input fuzzing. Use deterministic packet fault injection
and observable readiness barriers. Preserve application datagram boundaries;
do not retransmit application data or assume reliable close alerts.

Run native Windows `go test ./...`, Linux `make check`, relevant race tests,
and `make classic-parity` before committing a completed endpoint change.
Independent protocol/security review remains part of the merge decision.

Checks completed on 2026-09-05:

- Native Windows `go test ./...` and authenticated binary-to-binary DTLS relay.
- Linux `make check`, including lint, gosec, platform policy, Go tests, all 136
  Python tests, and the end-to-end suite including the DTLS binary relay.
- Linux race tests for the protocol and endpoint packages. Expanded algorithm
  interoperability includes 71 independent OpenSSL/wolfSSL/Pion cases; their
  transport limits are described above. Ten repeated ML-DSA-87 exchanges also
  passed under the race detector after increasing the receive queue.
- Twelve additional wolfSSL CID cases cover both roles, all ciphers, repeated
  immediate rotation and lost rotation ACKs at MTU 1200. The exact scope and
  remaining CID/migration gaps are described above.
- Linux `make classic-parity`: no missing/unexpected interface names or alias
  mismatches, and no drift from the reviewed official master. This is an
  interface audit, not evidence of classic DTLS 1.3 interoperability.
- The five official DTLS scorecard cases were rerun: four FAILED and one
  TIMEOUT. The file-transfer/default-block-size defect remains open; the
  system OpenSSL cases explicitly use DTLS 1.2. Full historical scorecard
  snapshots were not replaced by this subset. See
  [the current branch results](../testdata/scorecard/README.md#dtls-13-branch-checks-2026-09-05).
- Cross-builds for macOS arm64/amd64 and Linux/Windows 386. Native macOS tests
  remain for the repository CI matrix.
- Independent Python schedule vectors and Go fuzzing of records (6.1 million
  executions), fragments (1.2 million), hellos/ACKs (2.5 million), and CID lists
  (1.16 million). These bounded campaigns are not a cryptographic audit.
- Regression checks demonstrably fail when the fixed-address association
  routing, pending-CID ordering, or proactive AEAD key-rotation protections
  are removed.

OpenSSL and wolfSSL checks exercise the public UDP connection/listener API.
The Pion tests use protocol drivers for the CID-management limitation above.
Further independent review and optional follow-ups are listed in
[the plaintext follow-up plan](dtls13-follow-up.txt).

Protocol checks added on 2026-09-05 cover key-update ACK loss, simultaneous
updates, epoch-bit rollover, bounded spare CID pools, immediate CID rotation,
reordered CID/KeyUpdate flights, NAT rebinding, off-path forwarding, forged
records, cookie/address mismatches, nested rebinding, and amplification limits.
Linux package lint, gosec, race tests, and the OpenSSL/wolfSSL exchanges passed
after the protocol changes. Reordered data is filtered using the closure
alert's record number. Legacy record versions are ignored, and ServerHello
leaves its legacy session ID empty even when ClientHello supplies one.

Immediate CID updates also replace the CID held by a pending new-path probe,
so RRC responses and completed validation cannot restore the superseded CID.
An unrelated immediate update leaves a spare request pending; a spare
response, including an empty response, fulfills it. Three deterministic
regressions reproduce the old failures, with additional checks for ACK-only
peers, delayed spare responses and application traffic after migration.

Sustained spare issuance remains limited by the bounded local CID pool:
consuming a spare does not retire previously issued identifiers. Once that
pool fills, further requests receive empty responses until an explicit
immediate rotation retires the old pool. Automatic renewal beyond this bound
remains follow-up work; it is distinct from the two state bugs fixed above.

Key updates wait for acknowledgements of both the update and preceding
post-handshake messages. New post-handshake messages wait until the new sending
epoch is active. This conservative ordering follows the proposed clarification
in RFC 9147 erratum 8047 (still **Reported**, not a verified erratum). Sending
handshake sequence numbers never wrap; an exhausted association must close.
Old receiving keys remain available until authenticated traffic arrives under
the new keys. Sending keys rotate before the conservative AES record limit;
the connection event loop drives a queued update before resuming writes.

## Implementation sequence

1. Pin references, build independent lab tools, and adapt/test key derivation
   and record protection with upstream attribution.
2. Implement bounded wire decoding, replay windows, fragmentation/reassembly,
   ACK tracking, and deterministic retransmission scheduling.
3. Implement certificate client/server handshakes and cookies. Prove each
   direction against independent wolfSSL and OpenSSL peers.
4. Implement application I/O, key updates, shutdown, and session isolation.
5. Integrate DTLS endpoints/options/help with current xio lifecycle helpers;
   complete connection-ID/RRC support, including migration tests.
6. Complete interoperability/fault/security validation and repository checks.
