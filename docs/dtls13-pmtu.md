# DTLS PMTU

RFC 9147 §4.4 and RFC 8899, checked 2026-09-07.

`dtls-mtu` is the UDP payload ceiling including DTLS overhead. `Conn.MaxDatagramSize()`
is the application payload (MPS) after that overhead. Handshake recovery can
lower the current usable payload toward 256 bytes; that floor is a fragment
budget, not RFC 8899 `MIN_PLPMTU` (IPv4 68-byte / IPv6 1280-byte IP packets,
UDP payloads 40 and 1232) and not RFC 9147's ICMP-ignore floors (576 / 1280
IP). Default `dtls-mtu` remains 1200.

## Handshake recovery

`EMSGSIZE` on a handshake send reduces that association's fragment budget
and retries with a new record sequence. Unanswered handshake retransmits
shrink the same way when no ACK arrived; ordinary loss that makes progress
does not. Reductions stop at 256 bytes and after eight steps. The
configured MTU remains the ceiling. Application writes still surface the
transport error. `Conn.MaxDatagramSize()` tracks the current budget.

## Padded RRC probes (no search yet)

When RRC is negotiated and a dedicated UDP socket opted into unfragmented
sends (`Config.UnfragmentedProbes`), an association may send one padded
`path_challenge` of an exact candidate datagram size. Matching
`path_response` values are accepted against cookie, path, deadline and
generation. `path_drop`, loss, duplicates, wrong cookies/paths, and
old-path replies after migration do not raise the usable size. Responses
stay unpadded. Discovery does not consume spare CIDs, bind a new address,
or block `Conn.Write`. Automatic upward search is disabled until that
path is tested.

Linux opt-in uses `IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE` (DF set, kernel
ICMP PMTU tracking ignored). `IP_PMTUDISC_DO` is not used. Listeners ignore
the flag: a shared socket must not change fragmentation for every
association. Probe timeout is 16s (RFC 8899: never below 1s, should be
larger than 15s) and is included in `session.deadline()` so the connection
event loop wakes. The 600s raise timer is not started. In-flight migration
or KeyUpdate takes precedence: a matching response does not complete
discovery. Responses are matched against cookie, path (remote and local
socket), deadline, and generation.

We do not query `IP_MTU`, connect the active socket, or probe from another
source port.

## Path-size notes

The lab's loopback `lo` MTU is 65536; DF writes succeeded up to 65507 bytes.

On `enp3s0` (MTU 1500) with `IP_PMTUDISC_DO`, a connected-style UDP write
of 1473 bytes to `192.168.86.1:9` or `1.1.1.1:9` returns
`sendto: message too long`. 1472 succeeds (1500 − 20 − 8). That `DO`
behavior is the ICMP-tracking mode we refuse for probes.

Default `dtls-mtu=1200` stays under that Ethernet payload. The failure
shows up when a caller raises `dtls-mtu` above the path, or on a 1280-byte
path (Tailscale) if the UDP payload plus IP/UDP headers exceeds it.

## Still not done

1. Upward search, confirmation of the working size, and the 600s raise
   timer. Matching a probe must not yet change `MaxDatagramSize()`.
2. Lab captures proving unfragmented probes on IPv4/IPv6 with ICMP blocked.
3. A destination-specific PMTU query that preserves migration. Linux
   [`IP_MTU`](https://man7.org/linux/man-pages/man2/IP_MTU.2const.html)
   requires a connected socket. Do not connect the active socket just to
   query PMTU.
4. Per-datagram DF. Socket-wide `PROBE` remains dedicated-socket opt-in.
