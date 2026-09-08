# DTLS PMTU

RFC 9147 §4.4 and RFC 8899, checked 2026-09-07.

`dtls-mtu` is the UDP payload ceiling including DTLS overhead. `Conn.MaxDatagramSize()`
is the application payload (MPS) after that overhead. Handshake recovery can
lower the current usable payload toward 256 bytes; that floor is a fragment
budget, not RFC 8899 `MIN_PLPMTU` (IPv4 68-byte / IPv6 1280-byte IP packets,
UDP payloads 40 and 1232) and not RFC 9147's ICMP-ignore floors (576 / 1280
IP). Default `dtls-mtu` remains 1200.

## Defaults and scope

Command-line DTLS clients enable MTU confirmation and upward discovery by
default when migration is enabled. `dtls-unfragmented-probes=0` disables
discovery; handshake shrink remains automatic. Search requires a dedicated
UDP socket with successful unfragmented-send setup, negotiated CID/RRC, and
acknowledgement of the final handshake flight. Shared listeners never search.
The ceiling remains `dtls-mtu`: enabling discovery does not increase the
default 1200-byte ceiling, but allows recovery after a reduction.

Direct callers of `dtls13.Client` request this socket policy explicitly with
`Config.UnfragmentedProbes`. Custom packet transports cannot enable it.
Socket fragmentation policy changes only after successful CID/RRC negotiation;
peers without that support retain the original socket policy.

## Handshake recovery

`EMSGSIZE` on a handshake send reduces that association's fragment budget
and retries with a new record sequence. Unanswered handshake retransmits
shrink the same way when no ACK arrived; ordinary loss that makes progress
does not. Reductions stop at 256 bytes and after eight steps. The
configured MTU remains the ceiling. Application writes still surface the
transport error and are not retried at the datagram API; a too-big application
datagram reduces the advertised budget. The byte-stream adapter retries a
too-large write only when rejection before transmission is known and
`MaxDatagramSize()` strictly decreases. A transport that reports bytes sent
together with `EMSGSIZE` is not retried; the native error remains inspectable.
`Conn.MaxDatagramSize()` tracks the current budget.
A later higher PMTU is recovered only when unfragmented discovery is on.

## Padded RRC probes

When RRC is negotiated and a dedicated UDP socket has enabled unfragmented
sends, an association may send one padded `path_challenge` of an exact candidate
datagram size. Matching `path_response` values are accepted against cookie,
path, deadline and generation. `path_drop`, loss, duplicates, wrong
cookies/paths, and old-path replies after migration do not complete the
probe. Responses stay unpadded. Discovery does not consume spare CIDs, bind
a new address, or block `Conn.Write`. Manual probes still do not raise the
usable size.

Linux uses `IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE`. DF is set, and
outgoing size uses the interface MTU rather than a cached path MTU
(`ip_sk_use_pmtu` is false for PROBE). Incoming ICMP PTB can still update the
route cache; PROBE just does not consult that cache when sending.
`IP_PMTUDISC_DO` is not used. Windows uses `IP_MTU_DISCOVER=IP_PMTUDISC_PROBE`
for every enabled socket address family (IPv4, IPv6, or both). If setup
fails, automatic discovery stays disabled; DF alone is insufficient to
prove cache bypass. Listeners ignore the flag: a
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

## Validation

Session tests cover search, confirmation, isolated loss, black holes,
`EMSGSIZE`, the 600-second raise cycle and migration generations.
Stream tests check safe re-packetization and ambiguous transport errors
without losing or duplicating data. Datagram writes remain strict.

Linux tests in `internal/xio/privileged/dtls_pmtu_linux_test.go` use separate
client, router and server network namespaces with 1500-byte veth interfaces:

- Change the router's downstream MTU 1500 → 1280 → 1500 on a live DTLS
  association, block ICMP PTB, and verify shrink followed by authenticated
  RRC growth and application delivery. Recovery uses production timers;
  the link is restored during the recovery search, not after a raise cycle.
- Learn PMTU 1280 from real router ICMP, then restore the link. A throwaway
  `PMTUDISC_DO` socket still rejects 1400 bytes while the actual DTLS client
  completes authentication and delivers larger application datagrams.
- After negotiation, capture probe/application IPv4 DF/fragment flags,
  IPv6 absence of fragmentation headers, and complete packet lengths.
  Both cases run for IPv4 and IPv6.

These require root, `iproute2` and `iptables`/`ip6tables`. They run in the
existing privileged CI job, not ordinary `go test` or `make check`:

```sh
sudo "$(command -v go)" test -race -count=1 -v -tags=privileged ./internal/xio/privileged
```

Both routed cases passed with the race detector on the Linux lab VM and
[Linux CI](https://github.com/oittaa/socat/actions/runs/34185118250/job/101931786673)
on 2026-09-08. Maximum application payloads during shrink/recovery were
1442 → 706 → 1430 bytes for IPv4 and 1422 → 696 → 1410 for IPv6. These tests
configure larger ceilings to exercise the 1500 → 1280 → 1500 IP-MTU change.
The 600-second periodic raise cycle is covered by session tests; the routed
test restores the link while recovery search is active.

## Remaining

- Routed validation on Windows and macOS. Windows native tests check PROBE
  on IPv4, IPv6-only and dual-stack sockets; they do not prove cache bypass.
- A destination-specific PMTU query that preserves migration. Linux
  `IP_MTU` requires a connected socket; do not connect the active socket
  just to query it.
- Per-datagram DF for discovery on shared listeners. Current socket-wide
  fragmentation settings remain restricted to dedicated clients.
