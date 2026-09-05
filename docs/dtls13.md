# DTLS 1.3 implementation

Status: implemented and validated; independent security review is recommended before merge.

Implemented foundations: AES record protection and header masking, replay
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

Implement DTLS 1.3 over UDP on Linux, macOS, and Windows, using only Go
standard-library imports in the protocol package. Reuse the existing endpoint
and credential infrastructure. Do not implement DTLS 1.0 or 1.2, stream TLS
fallback, SCTP, or a WebRTC/ICE/SRTP stack.

The initial certificate-based profile includes AES-128-GCM/SHA-256 and
AES-256-GCM/SHA-384, P-256 and X25519, RSA/ECDSA/Ed25519 authentication, client
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
four queued encrypted datagrams and sixteen queued application datagrams;
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
and 2048–8192-bit RSA signing keys. Connection-level admission and lifetime
limits must bound aggregate memory before endpoint registration.

## Sources and compatibility baseline

- RFC 9147 defines the DTLS changes to the TLS 1.3 protocol in RFC 8446.
  Apply verified errata. RFC 9853 specifies return routability with connection IDs.
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
The opt-in `scripts/dtls13-lab.py` builds wolfSSL 5.9.2, BoringSSL's test shim,
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
against wolfSSL with both AES suites and P-256. Our server completed the same
checks against the OpenSSL client with both AES suites and both P-256/X25519.
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
peers with loss and reordering; independent coverage of that subprotocol
remains a limitation of the current references.

The Pion helper is built inside the isolated reference checkout; its imports
are not dependencies of socat's module. The opt-in tests
require an explicit manifest and never download dependencies:

```sh
SOCAT_DTLS13_TOOLS="$HOME/socat-dtls13-lab/tools.json" \
  go test -tags dtlsinterop ./internal/dtls13 -run TestInterop -v
```

Acceptance requires both client/server directions against independent peers,
verified 1.3 negotiation, certificate success/failure cases, AES suites and
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
- Linux race tests for the protocol and endpoint packages, including eight
  independent OpenSSL/wolfSSL/Pion interoperability cases.
- Linux `make classic-parity`: no missing/unexpected interface names or alias
  mismatches, and no drift from the reviewed official master. This is an
  interface audit, not evidence of classic DTLS 1.3 interoperability.
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
