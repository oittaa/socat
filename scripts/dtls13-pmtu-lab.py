#!/usr/bin/env python3
"""Exercise real DTLS PMTU timers through isolated Linux routers (no Docker)."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import itertools
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
import uuid


ROOT = Path(__file__).resolve().parent.parent
STOP = threading.Event()
# The search intentionally stops once its remaining uncertainty is <=20 bytes.
SEARCH_TOLERANCE = 20


def run(args, **kwargs):
    return subprocess.check_output([str(x) for x in args], text=True,
                                   stderr=subprocess.STDOUT, **kwargs).strip()


def packet_fields(frame):
    """Read Ethernet/IP/UDP lengths only; DTLS remains opaque."""
    kind = frame[12:14]
    data = frame[14:]
    if kind == b"\x08\x00" and len(data) >= 20:
        offset, protocol = (data[0] & 15) * 4, data[9]
        source, dest = data[12:16], data[16:20]
        bits = int.from_bytes(data[6:8], "big")
        fragment, df = bool(bits & 0x3fff), bool(bits & 0x4000)
    elif kind == b"\x86\xdd" and len(data) >= 40:
        offset, protocol = 40, data[6]
        source, dest = data[8:24], data[24:40]
        fragment, df = protocol == 44, None
    else:
        return None
    result = {"src": str(ipaddress.ip_address(source)), "dst": str(ipaddress.ip_address(dest)),
              "fragment": fragment, "df": df}
    if protocol == 17 and not fragment and len(data) >= offset + 8:
        _, result["port"], length = struct.unpack("!HHH", data[offset:offset + 6])
        result["udp_size"] = length - 8
    result["ptb"] = ((protocol == 1 and data[offset:offset + 2] == b"\x03\x04") or
                     (protocol == 58 and data[offset:offset + 1] == b"\x02"))
    return result


class Case:
    def __init__(self, args, family, icmp, reverse):
        self.args, self.family, self.icmp, self.reverse = args, family, icmp, reverse
        self.name = f"ipv{family}-{icmp}-{'reverse' if reverse else 'forward'}"
        self.directory = args.output / self.name
        self.directory.mkdir()
        self.prefix = "pm" + uuid.uuid4().hex[:8]
        self.ns = {name: f"{self.prefix}-{name}" for name in ("c", "a", "b", "s")}
        self.created, self.links, self.processes, self.readers = [], [], [], []
        self.reader_errors = []
        self.events = queue.Queue()
        self.priv = [] if os.geteuid() == 0 else ["sudo", "-n"]
        self.client_node, self.server_node = ("s", "c") if reverse else ("c", "s")
        self.client_ip = self.address(3 if reverse else 1, 2)
        self.server_ip = self.address(1 if reverse else 3, 2)
        self.low_udp = 1280 - (28 if family == 4 else 48)
        self.log = (self.directory / "events.jsonl").open("w")

    def address(self, subnet, host):
        return f"10.203.{subnet}.{host}" if self.family == 4 else f"fd00:203:{subnet}::{host}"

    def command(self, *args, node=None):
        prefix = list(self.priv)
        if node:
            prefix += ["ip", "netns", "exec", self.ns[node]]
        return run(prefix + list(args))

    def record(self, event, **fields):
        fields.update(event=event, time=time.time())
        self.log.write(json.dumps(fields) + "\n")
        self.log.flush()
        if event == "phase":
            print(f"{self.name}: {fields['phase']}", flush=True)

    def setup(self):
        for name in self.ns.values():
            self.command("ip", "netns", "add", name)
            self.created.append(name)
        for node in self.ns:
            self.command("ip", "link", "set", "lo", "up", node=node)
            self.command("sysctl", "-qw", f"net.ipv{self.family}.route.mtu_expires=3600", node=node)
        for index, (left, ld, right, rd, subnet) in enumerate([
                ("c", "c0", "a", "l0", 1), ("a", "t0", "b", "t0", 2), ("b", "r0", "s", "s0", 3)]):
            links = [f"{self.prefix}{index}{side}" for side in "ab"]
            self.command("ip", "link", "add", links[0], "type", "veth", "peer", "name", links[1])
            self.links.append(links[0])
            hosts = (2, 1) if subnet == 1 else (1, 2)
            for node, device, link, host in zip((left, right), (ld, rd), links, hosts):
                self.command("ip", "link", "set", link, "netns", self.ns[node])
                self.command("ip", "link", "set", link, "name", device, node=node)
                self.command("ip", "link", "set", device, "mtu", "1500", "up", node=node)
                suffix = "/24" if self.family == 4 else "/64"
                extra = [] if self.family == 4 else ["nodad"]
                self.command("ip", f"-{self.family}", "addr", "add",
                             self.address(subnet, host) + suffix, "dev", device, *extra, node=node)
        for node in ("a", "b"):
            self.command("sysctl", "-qw", "net.ipv4.ip_forward=1",
                         "net.ipv6.conf.all.forwarding=1", node=node)
            if self.icmp == "blocked":
                self.command("nft", "add", "table", "inet", "pmtu", node=node)
                self.command("nft", "add", "chain", "inet", "pmtu", "output",
                             "{ type filter hook output priority 0; policy accept; }", node=node)
                self.command("nft", "add", "rule", "inet", "pmtu", "output",
                             "ip", "protocol", "icmp", "icmp", "type", "3", "icmp", "code", "4", "drop", node=node)
                self.command("nft", "add", "rule", "inet", "pmtu", "output",
                             "meta", "l4proto", "ipv6-icmp", "icmpv6", "type", "2", "drop", node=node)
        for node, destination, gateway in [
                ("c", "default", self.address(1, 1)), ("s", "default", self.address(3, 1)),
                ("a", self.address(3, 0) + ("/24" if self.family == 4 else "/64"), self.address(2, 2)),
                ("b", self.address(1, 0) + ("/24" if self.family == 4 else "/64"), self.address(2, 1))]:
            self.command("ip", f"-{self.family}", "route", "add", destination, "via", gateway, node=node)
        for node in self.ns:
            self.record("network", node=node, links=self.command("ip", "-j", "addr", node=node),
                        routes=self.command("ip", f"-{self.family}", "-j", "route", node=node))

    def spawn(self, name, node, argv, capture=False):
        process = subprocess.Popen(self.priv + ["ip", "netns", "exec", self.ns[node]] + [str(x) for x in argv],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        self.processes.append(process)

        def stderr():
            with (self.directory / f"{name}.stderr").open("wb") as output:
                for line in process.stderr:
                    output.write(line)
                    if capture and b"listening on" in line:
                        self.events.put({"event": "capture_ready", "source": name})

        def stdout():
            try:
                if capture:
                    self.capture(name, process.stdout)
                else:
                    for line in process.stdout:
                        event = json.loads(line)
                        event.update(source=name)
                        self.events.put(event)
            except Exception as error:
                self.reader_errors.append(f"{name}: {error}")
                self.events.put({"event": "error", "source": name, "error": str(error)})
            self.events.put({"event": "exited", "source": name})

        for target in (stderr, stdout):
            thread = threading.Thread(target=target, daemon=True)
            self.readers.append(thread)
            thread.start()
        return process

    def capture(self, name, stream):
        with (self.directory / f"{name}.pcap").open("wb") as output:
            header = stream.read(24)
            output.write(header)
            endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(header[:4])
            if endian is None or struct.unpack(endian + "I", header[20:24])[0] != 1:
                raise RuntimeError("expected microsecond Ethernet pcap from tcpdump")
            while raw := stream.read(16):
                seconds, micros, length, _ = struct.unpack(endian + "IIII", raw)
                frame = stream.read(length)
                output.write(raw + frame)
                fields = packet_fields(frame)
                if fields:
                    fields.update(event="packet", source=name, time=seconds + micros / 1e6)
                    self.events.put(fields)

    def next_event(self, deadline):
        while time.monotonic() < deadline and not STOP.is_set():
            try:
                event = self.events.get(timeout=1)
            except queue.Empty:
                continue
            self.record("observation", value=event)
            if event["event"] in ("error", "exited"):
                raise RuntimeError(f"{event}; see stderr logs")
            return event
        raise TimeoutError("case deadline exceeded or interrupted")

    def wait_event(self, event, deadline):
        while (value := self.next_event(deadline))["event"] != event:
            pass
        return value

    def transit_mtu(self, size):
        for node in ("a", "b"):
            self.command("ip", "link", "set", "t0", "mtu", str(size), node=node)
        self.record("transit_mtu", value=size)

    def cache_check(self, seed=False):
        # A separate ordinary PMTUD socket demonstrates a real destination-cache
        # limit. It never changes options on the live DTLS socket.
        program = """
import errno, socket, sys
family, peer, seed = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
# Linux UAPI values; older Python versions do not export these names.
IP_MTU_DISCOVER, IPV6_MTU_DISCOVER, PMTUDISC_DO = 10, 23, 2
s = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP if family == 4 else socket.IPPROTO_IPV6,
             IP_MTU_DISCOVER if family == 4 else IPV6_MTU_DISCOVER, PMTUDISC_DO)
s.settimeout(2)
s.connect((peer, 9))
if seed:
    try:
        s.send(bytes(1440))
        s.recv(1)
    except OSError:
        pass
try:
    s.send(bytes(1440))
except OSError as error:
    if error.errno == errno.EMSGSIZE:
        print('EMSGSIZE')
        sys.exit(0)
    raise
raise RuntimeError('ordinary PMTUD socket was not limited by the smaller cache entry')
"""
        result = self.command(sys.executable, "-c", program, str(self.family), self.server_ip,
                              "1" if seed else "0", node=self.client_node)
        self.record("cache", result=result,
                    route=self.command("ip", f"-{self.family}", "-j", "route", "get", self.server_ip,
                                       node=self.client_node))

    def exercise(self):
        deadline = time.monotonic() + self.args.timeout
        for node, name in [(self.client_node, "before"), (self.server_node, "after")]:
            self.spawn(name, node, ["tcpdump", "-n", "-U", "-s", "0", "-i", "c0" if node == "c" else "s0", "-w", "-"], capture=True)
            self.wait_event("capture_ready", deadline)
        destination = f"{self.server_ip}:4433" if self.family == 4 else f"[{self.server_ip}]:4433"
        common = [self.args.binary, "-credentials", self.args.output]
        self.spawn("server", self.server_node, common + ["-listen", destination])
        self.wait_event("listening", deadline)
        client = self.spawn("client", self.client_node, common + ["-connect", destination])
        ready_event = self.wait_event("ready", deadline)
        ready = ready_event["time"] / 1e9
        initial_maximum = ready_event["max_datagram"]
        overhead = 1440 - initial_maximum
        phase, maximum, low_maximum = "initial", 0, 0
        lowered, restored, low_confirmed = 0, 0, 0
        first_reduced = None
        saw_initial_probe, grew, sample_pending = False, False, False
        misses, ptbs = 0, 0
        self.record("phase", phase=phase)
        while True:
            event = self.next_event(deadline)
            if event["event"] == "packet":
                if event["time"] < ready:
                    continue
                if event["source"] == "before" and event["ptb"] and event["dst"] == self.client_ip:
                    ptbs += 1
                    if self.icmp == "blocked":
                        raise RuntimeError("Packet Too Big reached client despite ICMP filter")
                if event["src"] != self.client_ip or event["dst"] != self.server_ip:
                    continue
                if event["fragment"] or (self.family == 4 and not event["df"]):
                    raise RuntimeError("client packet fragmented or lacked DF after handshake")
                size = event.get("udp_size", 0)
                if event["source"] == "after" and event.get("port") == 4433:
                    if phase == "initial" and size == 1440:
                        saw_initial_probe = True
                    # Once search has finished, its periodic confirmation uses
                    # the current working size. Search probes are strictly larger.
                    if (phase == "low" and self.low_udp - overhead - SEARCH_TOLERANCE <= maximum <= self.low_udp - overhead
                            and size == maximum + overhead):
                        low_confirmed = time.monotonic()
                        low_maximum = maximum
                        self.record("phase", phase="low-confirmed", max_datagram=maximum)
                        client.stdin.write(b"sample\n")
                        client.stdin.flush()
                        phase = "low-sample"
            elif event["event"] == "traffic":
                maximum = event["max_datagram"]
                if phase == "low" and maximum < initial_maximum and first_reduced is None:
                    first_reduced = time.monotonic() - lowered
                    self.record("reduced", max_datagram=maximum, elapsed=first_reduced)
                if event["sample"]:
                    if not event["ok"]:
                        raise RuntimeError(f"advertised maximum failed: {event}")
                    sample_pending = False
                    if phase == "initial-sample":
                        self.transit_mtu(1280)
                        lowered = time.monotonic()
                        if self.icmp == "allowed":
                            self.cache_check(seed=True)
                        phase = "low"
                        self.record("phase", phase=phase)
                    elif phase == "low-sample":
                        self.transit_mtu(1500)
                        restored = time.monotonic()
                        if self.icmp == "allowed":
                            self.cache_check()
                        phase = "recovery"
                        self.record("phase", phase=phase)
                    elif phase == "high-sample":
                        if self.icmp == "allowed":
                            self.cache_check()
                            if ptbs == 0:
                                raise RuntimeError("no real ICMP Packet Too Big was captured")
                        result = {"case": self.name, "status": "PASS", "low_max_datagram": low_maximum,
                                  "recovered_max_datagram": maximum, "ptb_received": ptbs,
                                  "first_shrink_seconds": round(first_reduced, 2),
                                  "low_confirmed_seconds": round(low_confirmed - lowered, 2),
                                  "recovery_seconds": round(time.monotonic() - restored, 2)}
                        client.stdin.write(b"stop\n")
                        client.stdin.flush()
                        return result
                else:
                    misses = 0 if event["ok"] else misses + 1
                    if misses >= 5:
                        raise RuntimeError("five consecutive small heartbeats lost")
                if phase == "initial" and saw_initial_probe and event["ok"]:
                    phase = "initial-sample"
                if phase == "recovery" and maximum > low_maximum:
                    grew = True
                    # The first periodic confirmation is ~60s into the 600s
                    # search interval. Early growth means we restored too soon.
                    if time.monotonic() - restored < 500:
                        raise RuntimeError("growth preceded the production periodic search restart")
                if (phase == "recovery" and grew
                        and initial_maximum - SEARCH_TOLERANCE <= maximum <= initial_maximum):
                    phase = "high-sample"
                if phase in ("initial-sample", "high-sample") and not sample_pending:
                    client.stdin.write(b"sample\n")
                    client.stdin.flush()
                    sample_pending = True

    def close(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                subprocess.run(self.priv + ["kill", "-TERM", "--", f"-{process.pid}"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    subprocess.run(self.priv + ["kill", "-KILL", "--", f"-{process.pid}"], check=False)
                    process.wait(timeout=3)
        for name in reversed(self.created):
            self.command("ip", "netns", "del", name)
        for link in self.links:
            subprocess.run(self.priv + ["ip", "link", "del", link],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        for thread in self.readers:
            thread.join(timeout=3)
            if thread.is_alive():
                self.reader_errors.append("capture/log reader did not finish")
        if self.reader_errors:
            raise RuntimeError("; ".join(self.reader_errors))

    def execute(self):
        try:
            if STOP.is_set():
                raise InterruptedError("interrupted before case setup")
            self.setup()
            result = self.exercise()
        except Exception as error:
            result = {"case": self.name, "status": "FAIL", "error": str(error)}
        finally:
            try:
                self.close()
            except Exception as error:
                result = {"case": self.name, "status": "FAIL", "error": f"cleanup: {error}"}
        self.record("result", **result)
        self.log.close()
        print(f"{self.name}: {result['status']} {result.get('error', '')}", flush=True)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "testdata" / "tmp" / time.strftime("pmtu-%Y%m%d-%H%M%S"))
    parser.add_argument("--family", choices=("4", "6", "both"), default="both")
    parser.add_argument("--icmp", choices=("allowed", "blocked", "both"), default="both")
    parser.add_argument("--direction", choices=("forward", "reverse", "both"), default="both")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=1800, help="per-case wall-clock bound in seconds; does not change DTLS timers")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("requires a Linux VM with network namespace support")
    os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/sbin:/sbin"
    if args.jobs < 1 or args.timeout < 1:
        parser.error("jobs and timeout must be positive")
    for tool in ("ip", "nft", "tcpdump", "go", "git", "sysctl", "kill"):
        if shutil.which(tool) is None:
            parser.error(f"missing {tool}; see docs/dtls13.md for dependencies")
    if os.geteuid() != 0:
        run(["sudo", "-n", "true"])
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    args.binary = args.output / "pmtu-peer"
    run(["go", "build", "-o", args.binary, "./internal/dtls13/testdata/pmtu_peer.go"], cwd=ROOT)
    run([args.binary, "-credentials", args.output, "-generate"])
    git = ["git", "-c", f"safe.directory={ROOT}"]
    metadata = {"revision": run(git + ["rev-parse", "HEAD"], cwd=ROOT),
                "changes": run(git + ["status", "--porcelain"], cwd=ROOT), "kernel": run(["uname", "-sr"]),
                "go": run(["go", "version"]), "ip": run(["ip", "-Version"]),
                "command": sys.argv, "timers": "production, including 600-second raise timer",
                "sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in (Path(__file__).resolve(), ROOT / "internal/dtls13/testdata/pmtu_peer.go")}}
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: STOP.set())
    families = (4, 6) if args.family == "both" else (int(args.family),)
    modes = ("allowed", "blocked") if args.icmp == "both" else (args.icmp,)
    directions = (False, True) if args.direction == "both" else (args.direction == "reverse",)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(Case(args, *case).execute) for case in itertools.product(families, modes, directions)]
        results = [future.result() for future in futures]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"Results and packet captures: {args.output}")
    return 0 if all(row["status"] == "PASS" for row in results) else 1


if __name__ == "__main__":
    sys.exit(main())
