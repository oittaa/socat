# DTLS PMTU investigation

RFC 9147 §4.4, checked 2026-09-07. Not an implementation.

## Split requirements

1. Expose available IP PMTU estimates and DTLS record expansion.
2. Report transport "datagram too big" errors and allow DF / no-fragment controls.
3. Handshake SHOULD fragment immediately if a message is too big, and SHOULD
   shrink record size after unanswered retransmits when PMTU is unknown.

Configured `dtls-mtu` (default 1200, range 256–65507) and handshake
fragmentation already exist. `Conn.MaxDatagramSize()` reports the current
record budget including CID overhead. We do not query `IP_MTU`, set
`IP_MTU_DISCOVER` / `IPV6_DONTFRAG`, or shrink fragments after loss.

OpenSSL's UDP BIO implements PMTU query and DF controls; do not describe
all peers as lacking those facilities.

## Reproduced path-size failure

Loopback `lo` MTU is 65536, so DF does not fail even at 65507 bytes.

On `enp3s0` (MTU 1500) with `IP_PMTUDISC_DO`, a connected-style UDP write
of 1473 bytes to `192.168.86.1:9` or `1.1.1.1:9` returns
`sendto: message too long`. 1472 succeeds (1500 − 20 − 8).

Default `dtls-mtu=1200` stays under that Ethernet payload. The failure
shows up when a caller raises `dtls-mtu` above the path, or on a 1280-byte
path (Tailscale) if the UDP payload plus IP/UDP headers exceeds it.

Shared DTLS listeners own one UDP socket for many associations. Setting DF
or a socket-wide MTU there would apply to every session.

## Smallest useful change (not done here)

1. Map `EMSGSIZE` / "message too long" from `WriteTo` to the existing
   record-overflow path so a handshake flight can fragment smaller, without
   changing the default MTU.
2. Query `IP_MTU` only on client-owned sockets after the first successful
   send, never on the shared listener.
3. Leave DF off by default; do not add a new transport framework.

Do not implement (1)–(3) until a session with `dtls-mtu` above the path
fails in-process and a test can inject `EMSGSIZE` without depending on
Ethernet.
