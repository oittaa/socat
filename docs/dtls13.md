# DTLS 1.3 status and interoperability

**Draft.** The packetizer and handshake receive-timeout blockers are resolved.
Independent protocol/security review and local CID coverage review remain
before merge. Unavailable independent spare-CID testing is not a blocker.

[User options and examples](../README.md#dtls-13) ·
[Standards and code map](dtls13-standards.md) ·
[Remaining work](dtls13-follow-up.txt)

## Implemented

Certificate-authenticated DTLS 1.3 over UDP on Linux, macOS and Windows:
cookies, SNI/ALPN, mutual authentication, fragmentation, selective ACKs,
retransmissions, replay protection, key updates, CID rotation and RFC 9853
enhanced path validation. Endpoints use the existing credentials, socket
options, peer filters, fork lifecycle, deadlines and cancellation.

Algorithm defaults match Go 1.27's TLS 1.3 set:

- AES-128/256-GCM and ChaCha20-Poly1305.
- X25519, P-256/P-384/P-521; X25519MLKEM768, SecP256r1MLKEM768 and
  SecP384r1MLKEM1024.
- RSA-PSS, ECDSA, Ed25519 and ML-DSA-44/65/87 authentication. The TLS ML-DSA
  mapping follows `draft-ietf-tls-mldsa-05`, still a draft at the review date.

Prefer Go primitives, generic signing and X.509 policy; `golang.org/x/`
packages are allowed. Keep protocol-required restrictions without extra local
security allowlists. `TestGoTLS13AlgorithmDefaults` detects default-set and
preference drift. New algorithms require wire integration; the test does not
enable them automatically or cover every Go `GODEBUG`/FIPS profile.

The stack adapts Pion's key derivation, AES protection and test vectors, not
its full protocol framework. Preserve the [attribution](../internal/dtls13/NOTICE.md)
and [MIT license](../internal/dtls13/LICENSE.pion). Pion interoperability
cannot detect bugs shared with that adapted code.

## Bounds and limitations

- Application delivery remains unordered and unreliable; close alerts may
  be lost. Packetization adds no application retransmission.
- Listener limits: 16 pending handshakes, 256 associations by default,
  8 MiB queued input and 16 MiB reassembly reservations. Pre-cookie output
  is capped at three times received bytes; migrated addresses must pass
  the peer filter.
- Each association has 256 input slots (655350 bytes total) and 256
  application slots (256 KiB total). Overflow is dropped. Reassembly allows
  1 MiB per message, 16 pending sequences and 2 MiB of message bodies.
- CID pools hold eight identifiers plus one temporary identifier during
  immediate rotation. Consuming a spare does not retire older CIDs. A full
  issuance pool returns empty responses until explicit immediate rotation
  retires it; automatic sustained renewal remains follow-up work.
- DTLS 1.0/1.2, PSKs, resumption, 0-RTT and post-handshake client
  authentication are not implemented. `EXEC,nofork` cannot use DTLS.

## Independent peers

Results checked on 2026-09-05. Exact revisions and build settings are in
[dtls13-baseline.json](../scripts/dtls13-baseline.json) and
[dtls13-lab.py](../scripts/dtls13-lab.py). These limits apply to the tested
revisions, not all future releases.

| Peer | Passing coverage | Limits |
| --- | --- | --- |
| OpenSSL 4.1 snapshot (`82733d9`) | Both roles; all 21 suite/group combinations; mutual ML-DSA-44/65/87. | No DTLS 1.3 CID support. Partial-flight ACK handling prevents the tested small-MTU PQ exchanges. |
| wolfSSL master (`d72f6d9`) | 21 suite/group combinations with our client. 12 mutual-auth CID cases in both roles: MTU 1200, all suites, P-256, request ACKs, repeated rotation with lost ACKs and KeyUpdate. | No spare issuance/replenishment or RFC 9853 RRC; migration interoperability remains unverified. |
| Pion (`59f4c33`) | Mutual authentication, bidirectional KeyUpdate and rebinding/RRC in both roles through protocol drivers using initial CIDs. | Rejects CID-management messages. Migration-enabled public endpoints proactively request spares and therefore do not fully interoperate. |
| BoringSSL (`4a92579`) | Test shim builds. | Packet-BIO adapter and interoperability tests remain undone. |

Algorithm tests use 4096-byte loopback MTUs where needed. The wolfSSL lab
build enables X25519 and enlarges its extra read buffer to 4096 bytes for
large hybrid offers. Earlier wolfSSL 5.9.2 server tests rejected fragmented
initial ClientHellos; both roles rejected post-handshake CID management.
Its tested tag was `v5.9.2-stable` (`ac01707f552c611fbd135cc723b2682b3e7f80f2`).

Local ML-DSA tests cover 256-byte datagrams, loss, reordering and final ACK
loss. Independent PQ loss/fragmentation coverage at normal MTUs remains open;
larger loopback tests do not establish it. None of the pinned peers supplies
independent spare-CID issuance/replenishment coverage.

The lab's system OpenSSL 3.5.5 supports only DTLS through 1.2. Unmodified
classic socat 1.8.1.3 cannot build against the pinned OpenSSL 4.1 headers
because it accesses opaque `ASN1_OCTET_STRING` fields. It is not a verified
DTLS 1.3 test peer. Keep development builds separate from system libraries
and the [official parity baseline](../scripts/classic-baseline.json).

## Validation

At `c2ec393`, all 26 CI checks passed, including Linux/macOS/Windows race
tests. Native Windows `go test ./...`, Linux `make check`, 20 repeated Linux
protocol/endpoint race runs and `make classic-parity` also passed. Earlier
opt-in runs covered 71 algorithm/Pion cases and the 12 wolfSSL CID cases above.

Deterministic regressions cover packetization, short reads, strict datagram
boundaries, queue limits, timeout precedence, listener isolation and CID/key
update ordering. Mutation checks demonstrate the relevant failures without
their fixes. Independent schedule vectors and bounded fuzz campaigns add
coverage; they do not constitute a completed security audit.

The unmodified official `OPENSSL_DTLS_TO_SERVER`, `OPENSSL_DTLS_TO_CLIENT`
and `RCVTIMEO_DTLS` cases pass. Two cases explicitly using DTLS 1.2 remain
unsupported. See the [scorecard](../testdata/scorecard/README.md#dtls-13-branch-checks-2026-09-05);
focused runs do not replace historical full-suite baselines.

## Run the lab

On Linux, install missing build prerequisites and build the pinned tools:

```sh
sudo apt-get install --no-install-recommends cmake ninja-build
python3 scripts/dtls13-lab.py
SOCAT_DTLS13_TOOLS="$HOME/socat-dtls13-lab/tools.json" \
  go test -tags dtlsinterop ./internal/dtls13 -run TestInterop -v
```

The lab keeps sources, builds, logs and `tools.json` under
`~/socat-dtls13-lab/`. `--only classic` attempts the separate classic/OpenSSL
build. These tools are test references, not runtime dependencies; ordinary
`make check` neither builds nor downloads them. Follow [AGENTS.md](../AGENTS.md)
for required checks and add focused race/interop tests for protocol changes.
