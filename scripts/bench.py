#!/usr/bin/env python3
"""Loopback socat benchmarks: classic C vs this Go binary.

Payload is a cached AES-128-CTR blob (incompressible). /dev/zero is not used
because any compress option would inflate those numbers.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MIB = 1024 * 1024

# AES-128-CTR key/iv: fixed so the payload is bit-identical across runs.
_AES_KEY = "0123456789abcdeffedcba9876543210"
_AES_IV = "00000000000000000000000000000000"

DEFAULT_CASES = (
    "tcp",
    "unix",
    "udplite",
    "tls",
    "quic",
    "tcp-rr",
    "tls-rr",
    "quic-rr",
    "tls-hs",
)
STREAM_CASES = {"tcp", "unix", "tls", "quic"}
DATAGRAM_CASES = {"udplite"}
RR_CASES = {"tcp-rr", "tls-rr", "quic-rr"}
HS_CASES = {"tls-hs"}
GO_ONLY = {"quic", "quic-rr"}
IPPROTO_UDPLITE = getattr(socket, "IPPROTO_UDPLITE", 136)
UDPLITE_MAGIC = b"SCL1"
UDPLITE_HEADER = struct.Struct("!4sQII")  # magic, sequence, payload length, CRC32
UDPLITE_MAX_DATAGRAM = 65507
UDPLITE_QUIET_SECONDS = 0.25


def parse_size(text: str) -> int:
    s = text.strip().lower().replace("ib", "")
    mult = 1
    if s.endswith("k"):
        mult = 1024
        s = s[:-1]
    elif s.endswith("m"):
        mult = MIB
        s = s[:-1]
    elif s.endswith("g"):
        mult = MIB * 1024
        s = s[:-1]
    return int(float(s) * mult)


def median(xs: list[float]) -> float:
    if not xs:
        return 0.0
    return float(statistics.median(xs))


def run_cmd(cmd: list[str], timeout: float = 30) -> str:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    return (p.stdout or "").strip()


def first_line(cmd: list[str]) -> str:
    try:
        out = run_cmd(cmd)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.splitlines()[0] if out else ""


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="ascii", errors="ignore").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def git_head(root: Path) -> str:
    try:
        return run_cmd(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return ""


def normalize_group(raw: str) -> str:
    s = (raw or "").strip()
    sl = s.lower().replace(" ", "")
    if "x25519mlkem768" in sl or "mlkem768" in sl:
        return "X25519MLKEM768"
    if "x25519" in sl:
        return "X25519"
    if "prime256v1" in sl or "secp256r1" in sl or sl.startswith("p-256") or "p256" in sl:
        return "P-256"
    return s


def parse_openssl_sclient(text: str) -> dict[str, str]:
    version = cipher = group_raw = ""
    for line in text.splitlines():
        l = line.strip()
        low = l.lower()
        if low.startswith("protocol version:"):
            version = l.split(":", 1)[1].strip()
        elif low.startswith("protocol") and ":" in l and "version" not in low:
            version = l.split(":", 1)[1].strip()
        elif low.startswith("ciphersuite:"):
            cipher = l.split(":", 1)[1].strip()
        elif "cipher is" in low:
            cipher = l.split("is", 1)[1].strip()
            if "tlsv1.3" in low:
                version = version or "TLSv1.3"
        elif low.startswith("cipher") and ":" in l:
            cipher = l.split(":", 1)[1].strip()
        elif "negotiated tls1.3 group:" in low:
            group_raw = l.split(":", 1)[1].strip()
        elif "server temp key:" in low or "peer temp key:" in low:
            group_raw = l.split(":", 1)[1].strip()
    return {
        "version": version,
        "cipher": cipher,
        "group": normalize_group(group_raw),
        "group_raw": group_raw,
    }


def probe_go_client(
    *,
    server_bin: str,
    proto: str,
    certs: dict[str, Path],
    workdir: Path,
    benchclient: Path,
    tag: str,
    impl: str = "go",
) -> dict[str, Any]:
    port = free_tcp_port()
    listen = echo_listen(proto if proto != "quic" else "quic", port, certs, fork=True, impl=impl)
    slog = workdir / "logs" / f"{tag}.server.log"
    server = start_socat(server_bin, [listen, "PIPE"], slog)
    try:
        if proto == "quic":
            wait_udp(port)
        else:
            wait_tcp(port)
        cmd = [
            str(benchclient),
            "-mode",
            "probe",
            "-proto",
            proto,
            "-addr",
            f"127.0.0.1:{port}",
            "-ca",
            str(certs["ca"]),
            "-servername",
            "localhost",
        ]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        if p.returncode != 0:
            err = (p.stdout or "") + (p.stderr or "")
            return {"ok": False, "error": err[-400:] or f"exit {p.returncode}"}
        data = json.loads(p.stdout)
        if not data.get("ok"):
            return {"ok": False, "error": data.get("error", "probe not ok")}
        return {
            "ok": True,
            "version": data.get("version", ""),
            "cipher": data.get("cipher", ""),
            "group": normalize_group(data.get("group", "")),
            "group_raw": data.get("group", ""),
            "alpn": data.get("alpn", ""),
            "client": "benchclient (crypto/tls or quic-go)",
            "server": server_bin,
        }
    finally:
        kill_proc(server)


def probe_openssl_sclient(
    *,
    server_bin: str,
    certs: dict[str, Path],
    workdir: Path,
    tag: str,
) -> dict[str, Any]:
    port = free_tcp_port()
    listen = echo_listen("tls", port, certs, fork=True, impl="classic")
    slog = workdir / "logs" / f"{tag}.server.log"
    server = start_socat(server_bin, [listen, "PIPE"], slog)
    try:
        wait_tcp(port)
        openssl_bin = os.environ.get("OPENSSL_BIN", "openssl")
        p = subprocess.run(
            [
                openssl_bin,
                "s_client",
                "-connect",
                f"127.0.0.1:{port}",
                "-CAfile",
                str(certs["ca"]),
                "-servername",
                "localhost",
            ],
            input="",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
        parsed = parse_openssl_sclient(p.stdout or "")
        if not parsed.get("cipher") and not parsed.get("version"):
            return {"ok": False, "error": (p.stdout or "openssl s_client failed")[-400:]}
        parsed["ok"] = True
        parsed["client"] = f"{openssl_bin} s_client"
        parsed["server"] = server_bin
        return parsed
    finally:
        kill_proc(server)


def probe_all(
    *,
    go_bin: str,
    classic_bin: str | None,
    certs: dict[str, Path],
    workdir: Path,
    benchclient: Path,
) -> dict[str, Any]:
    """Record the handshake each bench pairing actually negotiates."""
    out: dict[str, Any] = {}
    print("  probe go client / go TLS-LISTEN ...", flush=True)
    out["go_client_go_server"] = probe_go_client(
        server_bin=go_bin,
        proto="tls",
        certs=certs,
        workdir=workdir,
        benchclient=benchclient,
        tag="probe.go-go",
        impl="go",
    )
    print("  probe go client / go QUIC-LISTEN ...", flush=True)
    out["go_client_go_quic"] = probe_go_client(
        server_bin=go_bin,
        proto="quic",
        certs=certs,
        workdir=workdir,
        benchclient=benchclient,
        tag="probe.go-quic",
    )
    if classic_bin:
        print("  probe openssl s_client / classic OPENSSL-LISTEN ...", flush=True)
        out["openssl_client_classic_server"] = probe_openssl_sclient(
            server_bin=classic_bin,
            certs=certs,
            workdir=workdir,
            tag="probe.ossl-classic",
        )
        print("  probe go client / classic OPENSSL-LISTEN ...", flush=True)
        out["go_client_classic_server"] = probe_go_client(
            server_bin=classic_bin,
            proto="tls",
            certs=certs,
            workdir=workdir,
            benchclient=benchclient,
            tag="probe.go-classic",
            impl="classic",
        )
    return out


def collect_meta(args: dict[str, Any]) -> dict[str, Any]:
    go_bin = args["socat"]
    classic = args.get("classic")
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git": git_head(ROOT),
        "hostname": socket.gethostname(),
        "uname": f"{platform.system()} {platform.release()}",
        "cpu_model": cpu_model(),
        "nproc": os.cpu_count() or 0,
        "go_version": first_line(["go", "version"]),
        "go_socat": go_bin,
        "go_socat_version": first_line([go_bin, "-V"]),
        "classic_socat": classic or "",
        "classic_socat_version": first_line([classic, "-V"]) if classic else "",
        "openssl_bin": os.environ.get("OPENSSL_BIN", "openssl"),
        "openssl_version": first_line([os.environ.get("OPENSSL_BIN", "openssl"), "version"]),
        "size_bytes": args["size"],
        "runs": args["runs"],
        "warmup": args["warmup"],
        "buffer": args["buffer"],
        "payload": args["payload_note"],
        "payload_sha256": args["payload_sha256"],
        "payload_path": str(args["payload"]),
    }


def payload_sha256(path: Path, limit: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    n = 0
    with path.open("rb") as f:
        while n < limit:
            chunk = f.read(min(1024 * 1024, limit - n))
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
    return f"{h.hexdigest()} (first {n} bytes)"


def ensure_payload(workdir: Path, size: int) -> tuple[Path, str]:
    given = os.environ.get("BENCH_PAYLOAD", "").strip()
    if given:
        src = Path(given)
        if not src.is_file():
            raise SystemExit(f"BENCH_PAYLOAD is not a file: {src}")
        st = src.stat().st_size
        if st < size:
            raise SystemExit(
                f"BENCH_PAYLOAD {src} is {st} bytes; need at least {size}. "
                "Do not use /dev/zero (compressible)."
            )
        dest = workdir / f"payload.{size}"
        if not dest.is_file() or dest.stat().st_size != size:
            copy_prefix(src, dest, size)
        return dest, f"file:{src}"

    dest = workdir / f"payload.aes-ctr.{size}"
    shm = Path("/dev/shm")
    if os.access("/dev/shm", os.W_OK):
        dest = shm / f"socat-bench-payload.aes-ctr.{size}"
    if dest.is_file() and dest.stat().st_size == size:
        return dest, "aes-128-ctr (cached, incompressible)"
    generate_aes_ctr(dest, size)
    return dest, "aes-128-ctr (incompressible)"


def udplite_frame_count(size: int, buffer: int) -> int:
    if size <= 0:
        raise ValueError("UDP-Lite benchmark SIZE must be positive")
    if buffer <= UDPLITE_HEADER.size:
        raise ValueError(f"UDP-Lite BUF must exceed the {UDPLITE_HEADER.size}-byte frame header")
    if buffer > UDPLITE_MAX_DATAGRAM:
        raise ValueError(f"UDP-Lite BUF must not exceed {UDPLITE_MAX_DATAGRAM}")
    payload_per_frame = buffer - UDPLITE_HEADER.size
    return (size + payload_per_frame - 1) // payload_per_frame


def ensure_udplite_payload(payload: Path, size: int, buffer: int) -> tuple[Path, int, int]:
    """Frame SIZE source bytes into fixed-size, self-validating datagrams."""
    frame_count = udplite_frame_count(size, buffer)
    wire_size = frame_count * buffer
    stat = payload.stat()
    cache_key = hashlib.sha256(
        f"{payload.resolve()}:{stat.st_size}:{stat.st_mtime_ns}".encode("utf-8")
    ).hexdigest()[:12]
    dest = payload.with_name(f"{payload.name}.udplite-v1.{buffer}.{cache_key}")
    if dest.is_file() and dest.stat().st_size == wire_size:
        return dest, frame_count, wire_size

    payload_per_frame = buffer - UDPLITE_HEADER.size
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    written = 0
    with payload.open("rb") as source, tmp.open("wb") as out:
        for sequence in range(frame_count):
            payload_len = min(payload_per_frame, size - written)
            data = source.read(payload_len)
            if len(data) != payload_len:
                tmp.unlink(missing_ok=True)
                raise ValueError(f"UDP-Lite payload ended after {written + len(data)} bytes; want {size}")
            out.write(UDPLITE_HEADER.pack(UDPLITE_MAGIC, sequence, payload_len, zlib.crc32(data)))
            out.write(data)
            out.write(b"\x00" * (payload_per_frame - payload_len))
            written += payload_len
    if written != size or tmp.stat().st_size != wire_size:
        tmp.unlink(missing_ok=True)
        raise ValueError(f"failed to frame {size} UDP-Lite payload bytes")
    tmp.replace(dest)
    return dest, frame_count, wire_size


def analyze_udplite_sink(sink: Path, size: int, buffer: int) -> dict[str, Any]:
    """Validate fixed-size frames and report datagram delivery properties."""
    expected = udplite_frame_count(size, buffer)
    payload_per_frame = buffer - UDPLITE_HEADER.size
    seen: set[int] = set()
    received = duplicates = reordered = corrupt = trailing = 0
    received_payload = 0
    highest_sequence = -1

    if sink.is_file():
        with sink.open("rb") as source:
            while True:
                frame = source.read(buffer)
                if not frame:
                    break
                if len(frame) != buffer:
                    trailing = len(frame)
                    corrupt += 1
                    break
                magic, sequence, payload_len, checksum = UDPLITE_HEADER.unpack_from(frame)
                expected_len = 0
                if sequence < expected:
                    expected_len = min(payload_per_frame, size - sequence * payload_per_frame)
                data = frame[UDPLITE_HEADER.size : UDPLITE_HEADER.size + payload_len]
                if (
                    magic != UDPLITE_MAGIC
                    or sequence >= expected
                    or payload_len != expected_len
                    or zlib.crc32(data) != checksum
                ):
                    corrupt += 1
                    continue
                received += 1
                if sequence in seen:
                    duplicates += 1
                    continue
                if sequence < highest_sequence:
                    reordered += 1
                highest_sequence = max(highest_sequence, sequence)
                seen.add(sequence)
                received_payload += payload_len

    missing = expected - len(seen)
    return {
        "expected_datagrams": expected,
        "received_datagrams": received,
        "unique_datagrams": len(seen),
        "missing_datagrams": missing,
        "duplicate_datagrams": duplicates,
        "reordered_datagrams": reordered,
        "corrupt_datagrams": corrupt,
        "trailing_bytes": trailing,
        "loss_pct": 100.0 * missing / expected,
        "received_payload_bytes": received_payload,
        "received_wire_bytes": len(seen) * buffer,
    }


def copy_prefix(src: Path, dest: Path, size: int) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    with src.open("rb") as inf, tmp.open("wb") as out:
        left = size
        while left > 0:
            chunk = inf.read(min(1024 * 1024, left))
            if not chunk:
                break
            out.write(chunk)
            left -= len(chunk)
    if tmp.stat().st_size != size:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"failed to copy {size} bytes from {src}")
    tmp.replace(dest)


def generate_aes_ctr(dest: Path, size: int) -> None:
    """Write SIZE bytes of AES-128-CTR(zeros). Fast to make; does not compress."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    # Read zeros only as the cipher input. The file we keep is ciphertext.
    dd = subprocess.Popen(
        ["dd", "if=/dev/zero", f"bs={MIB}", f"count={(size + MIB - 1) // MIB}", "status=none"],
        stdout=subprocess.PIPE,
    )
    assert dd.stdout is not None
    enc = subprocess.Popen(
        [
            os.environ.get("OPENSSL_BIN", "openssl"),
            "enc",
            "-aes-128-ctr",
            "-nosalt",
            "-K",
            _AES_KEY,
            "-iv",
            _AES_IV,
        ],
        stdin=dd.stdout,
        stdout=subprocess.PIPE,
    )
    dd.stdout.close()
    assert enc.stdout is not None
    written = 0
    with tmp.open("wb") as out:
        while written < size:
            chunk = enc.stdout.read(min(1024 * 1024, size - written))
            if not chunk:
                break
            out.write(chunk)
            written += len(chunk)
    enc.stdout.close()
    dd.wait(timeout=60)
    enc.wait(timeout=60)
    if written != size:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"payload generate wrote {written} bytes, want {size}")
    tmp.replace(dest)


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def free_udplite_port() -> int:
    # UDP-Lite has its own protocol/port namespace; a free TCP or UDP port
    # says nothing about whether this port is available for protocol 136.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, IPPROTO_UDPLITE) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_tcp(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
        except OSError:
            return
        time.sleep(0.02)
    raise TimeoutError(f"TCP listen on 127.0.0.1:{port} did not appear")


def wait_udp(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    addr = ("127.0.0.1", port)
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(addr)
        except OSError:
            return
        time.sleep(0.02)
    raise TimeoutError(f"UDP listen on 127.0.0.1:{port} did not appear")


def wait_udplite(port: int, timeout: float = 5.0) -> None:
    # UDP and UDP-Lite have distinct protocol/port namespaces.
    deadline = time.monotonic() + timeout
    addr = ("127.0.0.1", port)
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, IPPROTO_UDPLITE) as s:
                s.bind(addr)
        except OSError:
            return
        time.sleep(0.02)
    raise TimeoutError(f"UDP-Lite listen on 127.0.0.1:{port} did not appear")


def udplite_available() -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, IPPROTO_UDPLITE)
    except OSError:
        return False
    s.close()
    return True


def wait_unix(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(f"UNIX socket {path} did not appear")


def read_rss_kib(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", encoding="ascii", errors="ignore") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        return 0
    return 0


def children_of(pid: int) -> list[int]:
    try:
        text = Path(f"/proc/{pid}/task/{pid}/children").read_text(encoding="ascii", errors="ignore")
    except OSError:
        return []
    return [int(x) for x in text.split() if x.isdigit()]


def descendant_pids(root: int) -> set[int]:
    seen: set[int] = set()
    stack = [root]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        stack.extend(children_of(pid))
    return seen


def tree_rss_kib(pids: list[int]) -> int:
    total = 0
    found: set[int] = set()
    for p in pids:
        if p <= 0:
            continue
        found |= descendant_pids(p)
    for pid in found:
        total += read_rss_kib(pid)
    return total


class RSSSampler:
    def __init__(self, pids: list[int], interval: float = 0.05) -> None:
        self.pids = pids
        self.interval = interval
        self.peak = 0
        self._stop = threading.Event()
        self._th = threading.Thread(target=self._run, name="rss-sample", daemon=True)

    def start(self) -> None:
        self._th.start()

    def stop(self) -> int:
        self._stop.set()
        self._th.join(timeout=2)
        return self.peak

    def _run(self) -> None:
        while not self._stop.is_set():
            rss = tree_rss_kib(self.pids)
            if rss > self.peak:
                self.peak = rss
            self._stop.wait(self.interval)


def start_socat(bin_path: str, extra: list[str], log: Path) -> subprocess.Popen:
    args = [bin_path, "-b", os.environ.get("BUF", "8192"), "-t", "2", "-T", "60", *extra]
    log.parent.mkdir(parents=True, exist_ok=True)
    fh = log.open("w", encoding="utf-8")
    try:
        return subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=fh,
            stderr=fh,
            start_new_session=True,
        )
    finally:
        fh.close()


def kill_proc(p: subprocess.Popen | None) -> None:
    if p is None or p.poll() is not None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except OSError:
        try:
            p.terminate()
        except OSError:
            return
    try:
        p.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait(timeout=2)


def sink_dir() -> Path:
    if os.access("/dev/shm", os.W_OK):
        return Path("/dev/shm")
    return Path(os.environ["WORKDIR"])


def tls_type_names(impl: str) -> tuple[str, str]:
    if impl == "classic":
        return "OPENSSL-LISTEN", "OPENSSL"
    return "TLS-LISTEN", "TLS"


def stream_addrs(case: str, port: int, sock: Path, certs: dict[str, Path], impl: str = "go") -> tuple[str, str]:
    crt, key, ca = certs["crt"], certs["key"], certs["ca"]
    if case == "tcp":
        return (
            f"TCP4-LISTEN:{port},reuseaddr,bind=127.0.0.1",
            f"TCP4:127.0.0.1:{port}",
        )
    if case == "unix":
        return (
            f"UNIX-LISTEN:{sock},unlink-early,unlink-close",
            f"UNIX-CONNECT:{sock}",
        )
    if case == "tls":
        listen_t, conn_t = tls_type_names(impl)
        return (
            f"{listen_t}:{port},reuseaddr,bind=127.0.0.1,cert={crt},key={key},verify=0",
            f"{conn_t}:127.0.0.1:{port},verify=1,cafile={ca},commonname=localhost",
        )
    if case == "quic":
        return (
            f"QUIC-LISTEN:{port},reuseaddr,bind=127.0.0.1,cert={crt},key={key},verify=0",
            f"QUIC:127.0.0.1:{port},verify=1,cafile={ca},commonname=localhost",
        )
    if case == "udplite":
        # RECV+SENDTO: a stream of datagrams. Non-fork *-LISTEN is one-shot
        # (first packet then EOF) on this port; classic LISTEN stays connected.
        return (
            f"UDPLITE4-RECV:{port},reuseaddr,bind=127.0.0.1,rcvbuf=8388608,sndbuf=8388608",
            f"UDPLITE4-SENDTO:127.0.0.1:{port},sndbuf=8388608,rcvbuf=8388608",
        )
    raise ValueError(case)


def listen_wait(case: str, port: int, sock: Path) -> None:
    if case == "unix":
        wait_unix(sock)
    elif case == "quic":
        wait_udp(port)
    elif case == "udplite":
        wait_udplite(port)
    else:
        wait_tcp(port)


def wait_file_quiet(
    path: Path, timeout: float = 10.0, quiet: float = UDPLITE_QUIET_SECONDS
) -> tuple[int, float]:
    """Return the final size and observed completion time after the sink is quiet."""
    deadline = time.perf_counter() + timeout
    last_change = time.perf_counter()
    last_size = -1
    while True:
        size = path.stat().st_size if path.exists() else 0
        now = time.perf_counter()
        if size != last_size:
            last_size = size
            last_change = now
        elif now - last_change >= quiet:
            return size, last_change
        if now >= deadline:
            raise TimeoutError(f"datagram sink did not become quiet within {timeout:.1f}s")
        time.sleep(0.01)


def run_udplite_once(
    *,
    bin_path: str,
    payload: Path,
    size: int,
    buffer: int,
    certs: dict[str, Path],
    workdir: Path,
    tag: str,
) -> dict[str, Any]:
    framed_payload, _, wire_size = ensure_udplite_payload(payload, size, buffer)
    port = free_udplite_port()
    sock = workdir / f"{tag}.sock"
    sink = sink_dir() / f"socat-bench-sink.{tag}"
    sink.unlink(missing_ok=True)
    listen, connect = stream_addrs("udplite", port, sock, certs)
    slog = workdir / "logs" / f"{tag}.server.log"
    clog = workdir / "logs" / f"{tag}.client.log"
    server = start_socat(bin_path, ["-u", listen, f"OPEN:{sink},creat,trunc,wronly"], slog)
    sampler: RSSSampler | None = None
    try:
        wait_udplite(port)
        sampler = RSSSampler([server.pid])
        sampler.start()
        t0 = time.perf_counter()
        client = start_socat(bin_path, ["-u", f"OPEN:{framed_payload},rdonly", connect], clog)
        sampler.pids.append(client.pid)
        try:
            rc = client.wait(timeout=120)
        except subprocess.TimeoutExpired:
            kill_proc(client)
            raise TimeoutError("UDP-Lite client socat timed out") from None
        send_elapsed = time.perf_counter() - t0
        _, receive_completed_at = wait_file_quiet(sink)
        receive_elapsed = receive_completed_at - t0
        server_rc = server.poll()
        kill_proc(server)
        peak = sampler.stop()
        sampler = None
        if rc != 0:
            return {
                "status": "fail",
                "detail": f"client exit {rc}: {clog.read_text(encoding='utf-8', errors='replace')[-400:]}",
            }
        if server_rc not in {None, 0}:
            return {
                "status": "fail",
                "detail": f"server exit {server_rc}: {slog.read_text(encoding='utf-8', errors='replace')[-400:]}",
            }

        delivery = analyze_udplite_sink(sink, size, buffer)
        result: dict[str, Any] = {
            "status": "ok",
            "send_elapsed_s": send_elapsed,
            "receive_elapsed_s": receive_elapsed,
            "send_mib_s": (size / MIB) / send_elapsed if send_elapsed > 0 else 0.0,
            "receive_mib_s": (delivery["received_payload_bytes"] / MIB) / receive_elapsed
            if receive_elapsed > 0
            else 0.0,
            "peak_rss_kib": peak,
            "payload_bytes": size,
            "wire_bytes": wire_size,
            **delivery,
        }
        if delivery["unique_datagrams"] == 0:
            result["status"] = "fail"
            result["detail"] = "no valid UDP-Lite datagrams reached the sink"
        elif delivery["corrupt_datagrams"] or delivery["trailing_bytes"]:
            result["status"] = "fail"
            result["detail"] = (
                f"corrupt datagrams={delivery['corrupt_datagrams']} "
                f"trailing bytes={delivery['trailing_bytes']}"
            )
        return result
    finally:
        kill_proc(server)
        if sampler is not None:
            sampler.stop()
        sink.unlink(missing_ok=True)


def run_stream_once(
    *,
    impl: str,
    bin_path: str,
    case: str,
    payload: Path,
    size: int,
    certs: dict[str, Path],
    workdir: Path,
    tag: str,
) -> dict[str, Any]:
    port = free_tcp_port()
    sock = workdir / f"{tag}.sock"
    sink = sink_dir() / f"socat-bench-sink.{tag}"
    sink.unlink(missing_ok=True)
    if sock.exists():
        sock.unlink()
    listen, connect = stream_addrs(case, port, sock, certs, impl=impl)
    slog = workdir / "logs" / f"{tag}.server.log"
    clog = workdir / "logs" / f"{tag}.client.log"
    server = start_socat(bin_path, ["-u", listen, f"OPEN:{sink},creat,trunc,wronly"], slog)
    try:
        listen_wait(case, port, sock)
        sampler = RSSSampler([server.pid])
        sampler.start()
        t0 = time.perf_counter()
        client = start_socat(bin_path, ["-u", f"OPEN:{payload},rdonly", connect], clog)
        sampler.pids.append(client.pid)
        try:
            rc = client.wait(timeout=120)
        except subprocess.TimeoutExpired:
            kill_proc(client)
            raise TimeoutError("client socat timed out") from None
        elapsed = time.perf_counter() - t0
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            kill_proc(server)
        peak = sampler.stop()
        if rc != 0:
            return {
                "status": "fail",
                "detail": f"client exit {rc}: {clog.read_text(encoding='utf-8', errors='replace')[-400:]}",
            }
        got = sink.stat().st_size if sink.exists() else 0
        if got != size:
            detail = slog.read_text(encoding="utf-8", errors="replace")[-400:]
            return {
                "status": "fail",
                "detail": f"sink {got} bytes, want {size}. server: {detail}",
                "elapsed_s": elapsed,
                "peak_rss_kib": peak,
            }
        mib_s = (size / MIB) / elapsed if elapsed > 0 else 0.0
        return {
            "status": "ok",
            "elapsed_s": elapsed,
            "mib_s": mib_s,
            "peak_rss_kib": peak,
            "bytes": got,
        }
    finally:
        kill_proc(server)
        sink.unlink(missing_ok=True)
        if sock.exists():
            sock.unlink()


def echo_listen(case: str, port: int, certs: dict[str, Path], fork: bool, impl: str = "go") -> str:
    crt, key = certs["crt"], certs["key"]
    fork_opt = ",fork" if fork else ""
    if case in {"tcp", "tcp-rr"}:
        return f"TCP4-LISTEN:{port},reuseaddr,bind=127.0.0.1{fork_opt}"
    if case in {"tls", "tls-rr", "tls-hs"}:
        listen_t, _ = tls_type_names(impl)
        return (
            f"{listen_t}:{port},reuseaddr,bind=127.0.0.1{fork_opt},"
            f"cert={crt},key={key},verify=0"
        )
    if case in {"quic", "quic-rr"}:
        return (
            f"QUIC-LISTEN:{port},reuseaddr,bind=127.0.0.1{fork_opt},"
            f"cert={crt},key={key},verify=0"
        )
    raise ValueError(case)


def proto_of(case: str) -> str:
    if case.startswith("quic"):
        return "quic"
    if case.startswith("tls"):
        return "tls"
    return "tcp"


def run_client_once(
    *,
    impl: str,
    bin_path: str,
    case: str,
    certs: dict[str, Path],
    workdir: Path,
    benchclient: Path,
    tag: str,
    mode: str,
    n: int,
    warmup: int,
    size: int,
) -> dict[str, Any]:
    port = free_tcp_port()
    fork = mode == "hs"
    listen = echo_listen(case, port, certs, fork=fork, impl=impl)
    slog = workdir / "logs" / f"{tag}.server.log"
    server = start_socat(bin_path, [listen, "PIPE"], slog)
    try:
        if proto_of(case) == "quic":
            wait_udp(port)
        else:
            wait_tcp(port)
        sampler = RSSSampler([server.pid])
        sampler.start()
        cmd = [
            str(benchclient),
            "-mode",
            mode,
            "-proto",
            proto_of(case),
            "-addr",
            f"127.0.0.1:{port}",
            "-n",
            str(n),
            "-warmup",
            str(warmup),
            "-size",
            str(size),
            "-ca",
            str(certs["ca"]),
            "-servername",
            "localhost",
        ]
        t0 = time.perf_counter()
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        elapsed = time.perf_counter() - t0
        peak = sampler.stop()
        if p.returncode != 0:
            err = (p.stdout or "") + (p.stderr or "")
            return {
                "status": "fail",
                "detail": err[-500:] or f"benchclient exit {p.returncode}",
                "elapsed_s": elapsed,
                "peak_rss_kib": peak,
            }
        data = json.loads(p.stdout)
        if not data.get("ok"):
            return {
                "status": "fail",
                "detail": data.get("error", "benchclient not ok"),
                "elapsed_s": elapsed,
                "peak_rss_kib": peak,
            }
        out: dict[str, Any] = {
            "status": "ok",
            "elapsed_s": data.get("elapsed_s", elapsed),
            "peak_rss_kib": peak,
        }
        if mode == "rr":
            out["rtt_us"] = data.get("rtt_us")
            out["msgs_s"] = data.get("msgs_s")
        else:
            out["hs_s"] = data.get("hs_s")
        return out
    finally:
        kill_proc(server)


def summarize_stream(runs: list[dict[str, Any]]) -> dict[str, Any]:
    oks = [r for r in runs if r.get("status") == "ok"]
    if not oks:
        return {
            "status": "fail",
            "detail": runs[-1].get("detail", "all runs failed") if runs else "no runs",
        }
    mibs = [float(r["mib_s"]) for r in oks]
    rss = [int(r["peak_rss_kib"]) for r in oks]
    elapsed = [float(r["elapsed_s"]) for r in oks]
    return {
        "status": "ok" if len(oks) == len(runs) else "fail",
        "kind": "stream",
        "mib_s": {"median": median(mibs), "min": min(mibs), "max": max(mibs), "runs": mibs},
        "elapsed_s": {"median": median(elapsed), "min": min(elapsed), "max": max(elapsed)},
        "peak_rss_kib": max(rss),
        "ok_runs": len(oks),
        "n_runs": len(runs),
        "detail": "" if len(oks) == len(runs) else runs[-1].get("detail", ""),
    }


def summarize_datagram(runs: list[dict[str, Any]]) -> dict[str, Any]:
    oks = [r for r in runs if r.get("status") == "ok"]
    if not oks:
        return {
            "status": "fail",
            "detail": runs[-1].get("detail", "all runs failed") if runs else "no runs",
        }

    def rates(name: str) -> dict[str, Any]:
        values = [float(r[name]) for r in oks]
        return {"median": median(values), "min": min(values), "max": max(values), "runs": values}

    def counts(name: str) -> dict[str, Any]:
        values = [int(r[name]) for r in oks]
        return {"total": sum(values), "max": max(values), "runs": values}

    return {
        "status": "ok" if len(oks) == len(runs) else "fail",
        "kind": "datagram",
        "send_mib_s": rates("send_mib_s"),
        "receive_mib_s": rates("receive_mib_s"),
        "loss_pct": rates("loss_pct"),
        "duplicate_datagrams": counts("duplicate_datagrams"),
        "reordered_datagrams": counts("reordered_datagrams"),
        "corrupt_datagrams": counts("corrupt_datagrams"),
        "expected_datagrams": int(oks[0]["expected_datagrams"]),
        "peak_rss_kib": max(int(r["peak_rss_kib"]) for r in oks),
        "ok_runs": len(oks),
        "n_runs": len(runs),
        "detail": "" if len(oks) == len(runs) else runs[-1].get("detail", ""),
    }


def summarize_rr(runs: list[dict[str, Any]]) -> dict[str, Any]:
    oks = [r for r in runs if r.get("status") == "ok"]
    if not oks:
        return {
            "status": "fail",
            "detail": runs[-1].get("detail", "all runs failed") if runs else "no runs",
        }
    med = [float(r["rtt_us"]["median"]) for r in oks]
    p99 = [float(r["rtt_us"]["p99"]) for r in oks]
    rate = [float(r["msgs_s"]) for r in oks]
    rss = [int(r["peak_rss_kib"]) for r in oks]
    return {
        "status": "ok" if len(oks) == len(runs) else "fail",
        "kind": "rr",
        "rtt_us": {
            "median": median(med),
            "p99": median(p99),
            "min": min(med),
            "max": max(med),
            "runs_median": med,
        },
        "msgs_s": {"median": median(rate), "min": min(rate), "max": max(rate)},
        "peak_rss_kib": max(rss),
        "ok_runs": len(oks),
        "n_runs": len(runs),
        "detail": "" if len(oks) == len(runs) else runs[-1].get("detail", ""),
    }


def summarize_hs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    oks = [r for r in runs if r.get("status") == "ok"]
    if not oks:
        return {
            "status": "fail",
            "detail": runs[-1].get("detail", "all runs failed") if runs else "no runs",
        }
    rate = [float(r["hs_s"]) for r in oks]
    rss = [int(r["peak_rss_kib"]) for r in oks]
    return {
        "status": "ok" if len(oks) == len(runs) else "fail",
        "kind": "hs",
        "hs_s": {"median": median(rate), "min": min(rate), "max": max(rate), "runs": rate},
        "peak_rss_kib": max(rss),
        "ok_runs": len(oks),
        "n_runs": len(runs),
        "detail": "" if len(oks) == len(runs) else runs[-1].get("detail", ""),
    }


def write_summary(doc: dict[str, Any], path: Path) -> None:
    m = doc["meta"]
    lines = [
        f"timestamp={m.get('timestamp')}",
        f"git={m.get('git')}",
        f"hostname={m.get('hostname')}",
        f"uname={m.get('uname')}",
        f"cpu_model={m.get('cpu_model')}",
        f"nproc={m.get('nproc')}",
        f"go_version={m.get('go_version')}",
        f"classic_socat_version={m.get('classic_socat_version')}",
        f"size_bytes={m.get('size_bytes')}",
        f"runs={m.get('runs')}",
        f"payload={m.get('payload')}",
    ]
    tls = m.get("tls") or {}
    for key, row in tls.items():
        if not isinstance(row, dict):
            continue
        if row.get("ok"):
            lines.append(
                f"tls.{key}: version={row.get('version')} cipher={row.get('cipher')} "
                f"group={row.get('group')}"
            )
        else:
            lines.append(f"tls.{key}: fail {row.get('error', '')}")
    lines.append("")
    for c in doc["cases"]:
        ident = f"{c['id']}/{c['impl']}"
        st = c.get("status")
        if st != "ok":
            lines.append(f"{ident}: {st} {c.get('detail', '')}")
            continue
        if c.get("kind") == "stream":
            ms = c["mib_s"]
            lines.append(
                f"{ident}: {ms['median']:.1f} MiB/s "
                f"(min {ms['min']:.1f} max {ms['max']:.1f}) "
                f"peak_rss_kib={c['peak_rss_kib']}"
            )
        elif c.get("kind") == "datagram":
            send = c["send_mib_s"]
            receive = c["receive_mib_s"]
            loss = c["loss_pct"]
            lines.append(
                f"{ident}: send={send['median']:.1f} MiB/s "
                f"receive={receive['median']:.1f} MiB/s "
                f"loss={loss['median']:.3f}% "
                f"duplicate={c['duplicate_datagrams']['total']} "
                f"reordered={c['reordered_datagrams']['total']} "
                f"corrupt={c['corrupt_datagrams']['total']} "
                f"peak_rss_kib={c['peak_rss_kib']}"
            )
        elif c.get("kind") == "rr":
            r = c["rtt_us"]
            lines.append(
                f"{ident}: rtt_us median={r['median']:.1f} p99={r['p99']:.1f} "
                f"msgs_s={c['msgs_s']['median']:.0f} peak_rss_kib={c['peak_rss_kib']}"
            )
        elif c.get("kind") == "hs":
            h = c["hs_s"]
            lines.append(
                f"{ident}: {h['median']:.1f} hs/s "
                f"(min {h['min']:.1f} max {h['max']:.1f}) "
                f"peak_rss_kib={c['peak_rss_kib']}"
            )
        else:
            lines.append(f"{ident}: {st}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    workdir = Path(os.environ.get("WORKDIR", str(ROOT / "testdata/tmp/bench")))
    workdir.mkdir(parents=True, exist_ok=True)
    size = parse_size(os.environ.get("SIZE", "256M"))
    runs = int(os.environ.get("RUNS", "5"))
    warmup = int(os.environ.get("WARMUP", "1"))
    buffer = int(os.environ.get("BUF", "8192"))
    socat = os.environ.get("SOCAT", str(ROOT / "socat"))
    classic = os.environ.get("CLASSIC_SOCAT", "").strip()
    benchclient = Path(os.environ.get("BENCHCLIENT", str(workdir / "benchclient")))
    certs = {
        "ca": Path(os.environ["BENCH_CA"]),
        "crt": Path(os.environ["BENCH_CERT"]),
        "key": Path(os.environ["BENCH_KEY"]),
    }
    probe_only = os.environ.get("PROBE_ONLY", "") == "1"
    wanted = tuple(sys.argv[1:] or (() if probe_only else DEFAULT_CASES))
    for c in wanted:
        if c not in STREAM_CASES | DATAGRAM_CASES | RR_CASES | HS_CASES:
            raise SystemExit(f"unknown case {c}; want {', '.join(DEFAULT_CASES)}")

    if probe_only:
        print("probe TLS/QUIC handshakes (no timed cases)", flush=True)
        tls = probe_all(
            go_bin=socat,
            classic_bin=classic or None,
            certs=certs,
            workdir=workdir,
            benchclient=benchclient,
        )
        print(json.dumps(tls, indent=2), flush=True)
        save = os.environ.get("SAVE_BASELINE", "").strip()
        if save and Path(save).is_file():
            doc = json.loads(Path(save).read_text(encoding="utf-8"))
            doc.setdefault("meta", {})["tls"] = tls
            Path(save).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
            write_summary(doc, Path(save).with_suffix(".summary.txt"))
            print(f"updated tls probe in {save}", flush=True)
        return 0 if all(v.get("ok") for v in tls.values() if isinstance(v, dict)) else 1

    payload, payload_note = ensure_payload(workdir, size)
    args = {
        "socat": socat,
        "classic": classic or None,
        "size": size,
        "runs": runs,
        "warmup": warmup,
        "buffer": buffer,
        "payload": payload,
        "payload_note": payload_note,
        "payload_sha256": payload_sha256(payload),
    }
    doc: dict[str, Any] = {"meta": collect_meta(args), "cases": []}
    print("probe TLS/QUIC handshakes ...", flush=True)
    doc["meta"]["tls"] = probe_all(
        go_bin=socat,
        classic_bin=classic or None,
        certs=certs,
        workdir=workdir,
        benchclient=benchclient,
    )

    impls_for = []
    if classic:
        impls_for.append(("classic", classic))
    impls_for.append(("go", socat))

    rr_n = int(os.environ.get("RR_N", "20000"))
    rr_warmup = int(os.environ.get("RR_WARMUP", "1000"))
    rr_size = int(os.environ.get("RR_SIZE", "64"))
    hs_n = int(os.environ.get("HS_N", "200"))
    hs_warmup = int(os.environ.get("HS_WARMUP", "20"))

    print(
        f"payload={payload} ({payload_note}, {size} bytes)\n"
        f"go={socat}\nclassic={classic or '<none>'}\n"
        f"cases={','.join(wanted)} runs={runs} warmup={warmup}",
        flush=True,
    )

    for case in wanted:
        for impl, bin_path in impls_for:
            if case in GO_ONLY and impl != "go":
                doc["cases"].append(
                    {
                        "id": case,
                        "impl": impl,
                        "status": "skip",
                        "detail": "classic has no QUIC",
                    }
                )
                print(f"  skip {case}/{impl} (no QUIC in classic)", flush=True)
                continue
            if case in DATAGRAM_CASES and (platform.system() != "Linux" or not udplite_available()):
                doc["cases"].append(
                    {
                        "id": case,
                        "impl": impl,
                        "status": "skip",
                        "detail": "UDP-Lite not available (Linux IPPROTO_UDPLITE)",
                    }
                )
                print(f"  skip {case}/{impl} (no UDP-Lite)", flush=True)
                continue
            print(f"  run  {case}/{impl} ...", flush=True)
            samples: list[dict[str, Any]] = []
            try:
                if case in STREAM_CASES:
                    for i in range(warmup):
                        run_stream_once(
                            impl=impl,
                            bin_path=bin_path,
                            case=case,
                            payload=payload,
                            size=size,
                            certs=certs,
                            workdir=workdir,
                            tag=f"{case}.{impl}.warmup{i}",
                        )
                    for i in range(runs):
                        samples.append(
                            run_stream_once(
                                impl=impl,
                                bin_path=bin_path,
                                case=case,
                                payload=payload,
                                size=size,
                                certs=certs,
                                workdir=workdir,
                                tag=f"{case}.{impl}.{i}",
                            )
                        )
                    summary = summarize_stream(samples)
                elif case in DATAGRAM_CASES:
                    for i in range(warmup):
                        run_udplite_once(
                            bin_path=bin_path,
                            payload=payload,
                            size=size,
                            buffer=buffer,
                            certs=certs,
                            workdir=workdir,
                            tag=f"{case}.{impl}.warmup{i}",
                        )
                    for i in range(runs):
                        samples.append(
                            run_udplite_once(
                                bin_path=bin_path,
                                payload=payload,
                                size=size,
                                buffer=buffer,
                                certs=certs,
                                workdir=workdir,
                                tag=f"{case}.{impl}.{i}",
                            )
                        )
                    summary = summarize_datagram(samples)
                elif case in RR_CASES:
                    for i in range(warmup):
                        run_client_once(
                            impl=impl,
                            bin_path=bin_path,
                            case=case,
                            certs=certs,
                            workdir=workdir,
                            benchclient=benchclient,
                            tag=f"{case}.{impl}.warmup{i}",
                            mode="rr",
                            n=min(200, rr_n),
                            warmup=min(50, rr_warmup),
                            size=rr_size,
                        )
                    for i in range(runs):
                        samples.append(
                            run_client_once(
                                impl=impl,
                                bin_path=bin_path,
                                case=case,
                                certs=certs,
                                workdir=workdir,
                                benchclient=benchclient,
                                tag=f"{case}.{impl}.{i}",
                                mode="rr",
                                n=rr_n,
                                warmup=rr_warmup,
                                size=rr_size,
                            )
                        )
                    summary = summarize_rr(samples)
                else:
                    for i in range(warmup):
                        run_client_once(
                            impl=impl,
                            bin_path=bin_path,
                            case=case,
                            certs=certs,
                            workdir=workdir,
                            benchclient=benchclient,
                            tag=f"{case}.{impl}.warmup{i}",
                            mode="hs",
                            n=min(20, hs_n),
                            warmup=5,
                            size=1,
                        )
                    for i in range(runs):
                        samples.append(
                            run_client_once(
                                impl=impl,
                                bin_path=bin_path,
                                case=case,
                                certs=certs,
                                workdir=workdir,
                                benchclient=benchclient,
                                tag=f"{case}.{impl}.{i}",
                                mode="hs",
                                n=hs_n,
                                warmup=hs_warmup,
                                size=1,
                            )
                        )
                    summary = summarize_hs(samples)
            except Exception as exc:  # noqa: BLE001 — record and continue
                summary = {"status": "fail", "detail": str(exc)}
            row = {"id": case, "impl": impl, **summary}
            doc["cases"].append(row)
            if row.get("status") == "ok" and row.get("kind") == "stream":
                print(
                    f"       {row['mib_s']['median']:.1f} MiB/s  "
                    f"rss={row['peak_rss_kib']} KiB",
                    flush=True,
                )
            elif row.get("status") == "ok" and row.get("kind") == "datagram":
                print(
                    f"       send={row['send_mib_s']['median']:.1f} MiB/s  "
                    f"receive={row['receive_mib_s']['median']:.1f} MiB/s  "
                    f"loss={row['loss_pct']['median']:.3f}%  "
                    f"dup={row['duplicate_datagrams']['total']}  "
                    f"reorder={row['reordered_datagrams']['total']}  "
                    f"corrupt={row['corrupt_datagrams']['total']}  "
                    f"rss={row['peak_rss_kib']} KiB",
                    flush=True,
                )
            elif row.get("status") == "ok" and row.get("kind") == "rr":
                print(
                    f"       rtt={row['rtt_us']['median']:.1f} µs  "
                    f"p99={row['rtt_us']['p99']:.1f}  "
                    f"rss={row['peak_rss_kib']} KiB",
                    flush=True,
                )
            elif row.get("status") == "ok" and row.get("kind") == "hs":
                print(
                    f"       {row['hs_s']['median']:.1f} hs/s  "
                    f"rss={row['peak_rss_kib']} KiB",
                    flush=True,
                )
            else:
                print(f"       {row.get('status')} {row.get('detail', '')}", flush=True)

    out_json = Path(os.environ.get("BENCH_OUT", str(workdir / "results.json")))
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    summary_path = out_json.with_suffix(".summary.txt")
    write_summary(doc, summary_path)
    save = os.environ.get("SAVE_BASELINE", "").strip()
    if save:
        dest = Path(save)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        write_summary(doc, dest.with_suffix(".summary.txt"))
        print(f"saved baseline {dest}", flush=True)
    print(f"wrote {out_json}", flush=True)
    print(f"wrote {summary_path}", flush=True)

    failed = [c for c in doc["cases"] if c.get("status") == "fail"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
