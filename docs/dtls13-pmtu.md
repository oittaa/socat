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
transport error and are not retried at the datagram API; a too-big application
datagram reduces the advertised budget. The byte-stream adapter retries a
zero-byte too-large write only after `MaxDatagramSize()` strictly decreases.
`Conn.MaxDatagramSize()` tracks the current budget.
A later higher PMTU is recovered only when unfragmented discovery is on.

## Padded RRC probes

When RRC is negotiated and a dedicated UDP socket opted into unfragmented
sends (`Config.UnfragmentedProbes` / `dtls-unfragmented-probes`), an
association may send one padded `path_challenge` of an exact candidate
datagram size. Matching `path_response` values are accepted against cookie,
path, deadline and generation. `path_drop`, loss, duplicates, wrong
cookies/paths, and old-path replies after migration do not complete the
probe. Responses stay unpadded. Discovery does not consume spare CIDs, bind
a new address, or block `Conn.Write`. Manual probes still do not raise the
usable size.

Linux opt-in uses `IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE`. DF is set, and
outgoing size uses the interface MTU rather than a cached path MTU
(`ip_sk_use_pmtu` is false for PROBE). Incoming ICMP PTB can still update the
route cache; PROBE just does not consult that cache when sending.
`IP_PMTUDISC_DO` is not used. Windows uses `IP_MTU_DISCOVER=IP_PMTUDISC_PROBE`
when the stack accepts it (datagram PROBE: DF set, fail only above the
interface MTU). Older Windows stacks fall back to `IP_DONTFRAGMENT`, which
does not by itself bypass a cached path MTU. Listeners ignore the flag: a
shared socket must not change fragmentation for every association. We do not
query `IP_MTU`, connect the active socket, or probe from another source port.

## Confirmation and search

Discovery runs only when all of these hold: dedicated-socket DF succeeded
(`canProbe`), `UnfragmentedProbes`, handshake complete **and the final
flight acknowledged**, RRC, and CID. Shared listeners never search.
The post-handshake scheduler uses the same final-flight ACK gate.

After handshake, a shrink, an application `EMSGSIZE`, or a validated path
change, the association confirms the current working size, then searches
upward toward `dtls-mtu`. Search uses a bounded interval (quic-go
`mtu_discoverer.go` at `793f74d8e03368c5aded128af6f48d21dbb47f73`) that
tolerates two isolated losses; a third loss of larger sizes lowers the
search ceiling. `EMSGSIZE` on a search probe hard-rejects that size
without shrinking the working MTU. Confirm `EMSGSIZE` or three confirm
losses shrink the working size, then confirm again and search. Matching a
search probe larger than the working size raises it and clears the shrink
counter so a later drop can recover again.

Timers (synthetic `session.tick` in tests; included in `session.deadline()`):

| Timer | Value | Role |
| --- | --- | --- |
| Probe wait | 16s | RFC 8899 PROBE_TIMER: wait for `path_response` (MUST NOT be below 1s, SHOULD be >15s). |
| Probe pace | 1s | Spacing after an ack or loss. RFC 8899 §3 requires at least one RTT between probes when they are not congestion-controlled. DTLS application data has no ACK/RTT estimator; 1s is a conservative stand-in. The 1s MUST NOT in RFC 8899 applies to PROBE_TIMER, not this interval. |
| Confirm | 60s | While the path is in use (DTLS application data has no ACKs). Must be less than the raise timer. Does not restart search on success and does not reset the raise timer. |
| Raise | 600s | RFC 8899 PMTU_RAISE_TIMER. Restarts search from the current working size toward `dtls-mtu`. Expiry never restores the configured ceiling. |

The first confirm/search after handshake does not wait for application
writes, so a handshake shrink can recover immediately. Raise and periodic
confirm require a successful application send or received application data
since the last discovery probe. In-flight migration or KeyUpdate takes
precedence: a matching response does not complete discovery, and probes
are deferred until those finish.

ICMP Packet Too Big / PTB is unused by this stack (CVE-2024-53259). RFC 8899
§4.6.1 permits a simple implementation to ignore PTB messages; that choice
does not by itself make DPLPMTUD incomplete. Linux `PMTUDISC_PROBE` still
allows the kernel to update the route cache from PTB; it only skips that
cache when choosing the send size. Remaining gaps: no `IP_MTU` query, and
probe spacing is a fixed timer rather than one measured RTT.

## Path-size notes

The lab's loopback `lo` MTU is 65536; DF writes succeeded up to 65507 bytes.

On `enp3s0` (MTU 1500) with `IP_PMTUDISC_DO`, a connected-style UDP write
of 1473 bytes to `192.168.86.1:9` or `1.1.1.1:9` returns
`sendto: message too long`. 1472 succeeds (1500 − 20 − 8). That `DO`
behavior is the ICMP-tracking mode we refuse for probes.

Default `dtls-mtu=1200` stays under that Ethernet payload. The failure
shows up when a caller raises `dtls-mtu` above the path, or on a 1280-byte
path (Tailscale) if the UDP payload plus IP/UDP headers exceeds it.

Search, confirm, isolated loss, black-hole, `EMSGSIZE`, raise, and
migration generation are covered by session tests with a size-limited send
path (packets larger than a fake path MTU are dropped or return
`EMSGSIZE`). That is the ICMP-blocked stand-in: no PTB, DF probes either
time out or fail locally. Privileged Linux tests put a veth peer in a new
netns, lock a host-route MTU, and check that `PMTUDISC_PROBE` still delivers
a larger IPv4 and IPv6 datagram while a throwaway `PMTUDISC_DO` socket gets
`EMSGSIZE`. Those tests skip without root (`CAP_NET_ADMIN`). This environment
has no `CAP_NET_ADMIN` for a physical routed IPv4/IPv6 PMTU lab beyond that
veth pair.

## Still not done

1. Lab captures proving unfragmented probes on a real IPv4/IPv6 interface with
   ICMP blocked (needs `CAP_NET_ADMIN` and a controlled path MTU beyond veth).
2. A destination-specific PMTU query that preserves migration. Linux
   [`IP_MTU`](https://man7.org/linux/man-pages/man2/IP_MTU.2const.html)
   requires a connected socket. Do not connect the active socket just to
   query PMTU.
3. Per-datagram DF. Socket-wide `PROBE` remains dedicated-socket opt-in.
4. Confirm Windows `IP_PMTUDISC_PROBE` cache-bypass on a routed path. Native
   unit tests assert the sockopt is PROBE (not DO) when `IP_MTU_DISCOVER`
   is available.
