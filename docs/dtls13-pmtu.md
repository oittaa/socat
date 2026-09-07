# DTLS PMTU investigation

RFC 9147 §4.4, checked 2026-09-07. Not an implementation.

## Split requirements

1. Expose available IP PMTU estimates and DTLS record expansion.
2. Report transport "datagram too big" errors and allow DF / no-fragment controls.
3. Handshake SHOULD fragment immediately if a message is too big, and SHOULD
   shrink record size after unanswered retransmits when PMTU is unknown.

Configured `dtls-mtu` (default 1200, range 256–65507) and handshake
fragmentation already exist. `Conn.MaxDatagramSize()` reports the current
record budget including CID overhead. Handshake sends treat `EMSGSIZE` as a
recoverable local MTU failure: the association reduces its fragment budget
and retries, using the configured MTU as the ceiling. Unanswered handshake
flights shrink with the same bound. Application writes still surface the
transport error. We do not query `IP_MTU` or set `IP_MTU_DISCOVER` /
`IPV6_DONTFRAG`.

OpenSSL's UDP BIO implements PMTU query and DF controls; do not describe
all peers as lacking those facilities.

## Reproduced path-size failure

The lab's loopback `lo` MTU is 65536; DF writes succeeded up to 65507 bytes.

On `enp3s0` (MTU 1500) with `IP_PMTUDISC_DO`, a connected-style UDP write
of 1473 bytes to `192.168.86.1:9` or `1.1.1.1:9` returns
`sendto: message too long`. 1472 succeeds (1500 − 20 − 8).

Default `dtls-mtu=1200` stays under that Ethernet payload. The failure
shows up when a caller raises `dtls-mtu` above the path, or on a 1280-byte
path (Tailscale) if the UDP payload plus IP/UDP headers exceeds it.

Shared DTLS listeners own one UDP socket for many associations. Setting DF
or a socket-wide MTU there would apply to every session.

## Handshake recovery (implemented)

`EMSGSIZE` on a handshake send reduces that association's fragment budget
and retries with a new record sequence. Unanswered handshake retransmits
shrink the same way when no ACK arrived; ordinary loss that makes progress
does not. Reductions stop at 256 bytes and after eight steps. The
configured MTU remains the ceiling; the default stays 1200. Recovery is
not routed through fatal `record_overflow`. Shared listener sockets are
unchanged.

## Still not done

1. A destination-specific PMTU query that preserves migration. Linux
   [`IP_MTU`](https://man7.org/linux/man-pages/man2/IP_MTU.2const.html)
   requires a connected socket. Our client uses an unconnected `PacketConn`;
   a successful `WriteTo` does not connect it. Do not connect the active
   socket just to query PMTU or change the shared listener's socket state.
2. Preserve existing OS/user fragmentation settings. Do not assume DF is
   off or introduce socket-wide changes for one peer.
