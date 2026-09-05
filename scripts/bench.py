#!/usr/bin/env python3
"""Loopback socat benchmarks: classic C vs this Go binary.

Payload is a fresh AES-128-CTR blob (incompressible). /dev/zero is not used
because any compress option would inflate those numbers.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO

if os.name == "nt":
    import msvcrt
else:
    import fcntl

ROOT = Path(__file__).resolve().parent.parent
MIB = 1024 * 1024
STORAGE_RESERVE = 64 * MIB

DEFAULT_CASES = (
    "tcp",
    "unix",
    "udp",
    "tls",
    "ws",
    "wss",
    "quic",
    "dtls",
    "tcp-rr",
    "tls-rr",
    "quic-rr",
    "dtls-rr",
    "tls-hs",
    "dtls-hs",
)
STREAM_CASES = {"tcp", "unix", "tls", "ws", "wss", "quic"}
DATAGRAM_CASES = {"udp", "dtls"}
RR_CASES = {"tcp-rr", "tls-rr", "quic-rr", "dtls-rr"}
HS_CASES = {"tls-hs", "dtls-hs"}
GO_ONLY = {
    "ws": "WebSocket",
    "wss": "WebSocket",
    "quic": "QUIC",
    "quic-rr": "QUIC",
    "dtls": "DTLS",
    "dtls-rr": "DTLS",
    "dtls-hs": "DTLS",
}
UDP_PROTOS = {"quic", "dtls"}
DATAGRAM_MAGIC = b"SCL1"
DATAGRAM_HEADER = struct.Struct("!4sQII")  # magic, sequence, payload length, CRC32
DATAGRAM_MAX_SIZE = 65507
# Leave room for record protection and CID within DTLS's default 1200-byte MTU.
DTLS_FRAME_SIZE = 1024
DATAGRAM_QUIET_SECONDS = 0.25


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


def socat_version(cmd: list[str]) -> str:
    try:
        out = run_cmd(cmd)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    for line in lines:
        if line.lower().startswith("socat version "):
            return line
    return lines[0] if lines else ""


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="ascii", errors="ignore").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def git_head(root: Path) -> str:
    override = os.environ.get("SOCAT_BENCH_GIT_COMMIT", "").strip()
    if override:
        return override
    try:
        commit = run_cmd(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    is_hex = all(char in "0123456789abcdef" for char in commit.lower())
    if 7 <= len(commit) <= 40 and is_hex:
        return commit
    return ""


def env_enabled(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


def executable_name(name: str) -> str:
    return name + (".exe" if os.name == "nt" else "")


def run_checked(cmd: list[str], *, cwd: Path = ROOT, quiet: bool = False) -> None:
    try:
        completed = subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE if quiet else None,
            stderr=subprocess.STDOUT if quiet else None,
            text=quiet,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"required executable not found: {cmd[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = f": {(exc.stdout or '').strip()}" if quiet and exc.stdout else ""
        raise SystemExit(f"command failed ({exc.returncode}): {' '.join(cmd)}{detail}") from exc
    if quiet and not completed.stdout:
        raise SystemExit(f"command produced no result: {' '.join(cmd)}")


def build_go_binary(output: Path, package: str, *, versioned: bool = False) -> None:
    cmd = ["go", "build"]
    if versioned:
        version = run_cmd(
            ["git", "-C", str(ROOT), "describe", "--tags", "--always", "--dirty"],
            timeout=5,
        )
        if not version or version.startswith("fatal:"):
            version = os.environ.get("SOCAT_BENCH_GIT_COMMIT", "dev") or "dev"
        cmd += ["-ldflags", f"-s -w -X github.com/oittaa/socat.Version={version}"]
    cmd += ["-o", str(output), package]
    output.parent.mkdir(parents=True, exist_ok=True)
    run_checked(cmd)


def same_file(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve() == right.resolve()


def discover_classic(socat: Path) -> str:
    configured = os.environ.get("SOCAT_CLASSIC_BIN", "").strip()
    if configured:
        return configured
    candidate = shutil.which("socat")
    if candidate and not same_file(Path(candidate), socat):
        return candidate
    return ""


def generate_certs(benchclient: Path, cert_dir: Path) -> dict[str, Path]:
    names = {
        "ca": os.environ.get("SOCAT_BENCH_CA", "").strip(),
        "crt": os.environ.get("SOCAT_BENCH_CERT", "").strip(),
        "key": os.environ.get("SOCAT_BENCH_KEY", "").strip(),
    }
    if any(names.values()):
        if not all(names.values()):
            raise SystemExit("SOCAT_BENCH_CA, SOCAT_BENCH_CERT, and SOCAT_BENCH_KEY must be set together")
        certs = {name: Path(path) for name, path in names.items()}
        missing = [str(path) for path in certs.values() if not path.is_file()]
        if missing:
            raise SystemExit(f"benchmark certificate file not found: {', '.join(missing)}")
        return certs

    cert_dir.mkdir(parents=True, exist_ok=True)
    run_checked([str(benchclient), "-mode", "cert", "-cert-dir", str(cert_dir)], quiet=True)
    certs = {
        "ca": cert_dir / "ca.pem",
        "crt": cert_dir / "server.crt",
        "key": cert_dir / "server.key",
    }
    missing = [str(path) for path in certs.values() if not path.is_file()]
    if missing:
        raise SystemExit(f"benchmark certificate generation failed: {', '.join(missing)}")
    return certs


def setup_benchmark(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "logs").mkdir(exist_ok=True)

    configured_socat = os.environ.get("SOCAT_BIN", "").strip()
    socat = Path(configured_socat) if configured_socat else ROOT / executable_name("socat")
    if not env_enabled("SOCAT_BENCH_SKIP_BUILD") and not configured_socat:
        build_go_binary(socat, "./cmd/socat", versioned=True)
    if not socat.is_file() or not os.access(socat, os.X_OK):
        raise SystemExit(f"socat not found: {socat}")

    configured_client = os.environ.get("SOCAT_BENCH_CLIENT_BIN", "").strip()
    benchclient = (
        Path(configured_client) if configured_client else run_dir / executable_name("benchclient")
    )
    if not env_enabled("SOCAT_BENCH_SKIP_CLIENT_BUILD") and not configured_client:
        build_go_binary(benchclient, "./scripts/benchclient")
    if not benchclient.is_file() or not os.access(benchclient, os.X_OK):
        raise SystemExit(f"benchclient not found: {benchclient}")

    certs = generate_certs(benchclient, run_dir / "certs")
    openssl = os.environ.get("SOCAT_BENCH_OPENSSL_BIN", "").strip() or shutil.which("openssl") or ""

    classic = discover_classic(socat)
    if classic and not Path(classic).is_file():
        raise SystemExit(f"classic socat not found: {classic}")
    if not classic:
        print("classic socat was not found on PATH; classic cases will be skipped.", file=sys.stderr)

    os.environ["SOCAT_BIN"] = str(socat)
    os.environ["SOCAT_CLASSIC_BIN"] = classic
    os.environ["SOCAT_BENCH_CLIENT_BIN"] = str(benchclient)
    os.environ["SOCAT_BENCH_CA"] = str(certs["ca"])
    os.environ["SOCAT_BENCH_CERT"] = str(certs["crt"])
    os.environ["SOCAT_BENCH_KEY"] = str(certs["key"])
    os.environ["SOCAT_BENCH_OPENSSL_BIN"] = openssl


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
    run_dir: Path,
    benchclient: Path,
    tag: str,
    impl: str = "go",
) -> dict[str, Any]:
    port = free_tcp_port()
    listen = echo_listen(proto, port, certs, fork=True, impl=impl)
    slog = run_dir / "logs" / f"{tag}.server.log"
    server = start_socat(server_bin, [listen, "PIPE"], slog)
    try:
        if proto in UDP_PROTOS:
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
            "client": "benchclient (dtls13)" if proto == "dtls" else "benchclient (crypto/tls or quic-go)",
            "server": server_bin,
        }
    finally:
        kill_proc(server)


def probe_openssl_sclient(
    *,
    server_bin: str,
    certs: dict[str, Path],
    run_dir: Path,
    tag: str,
) -> dict[str, Any]:
    port = free_tcp_port()
    listen = echo_listen("tls", port, certs, fork=True, impl="classic")
    slog = run_dir / "logs" / f"{tag}.server.log"
    server = start_socat(server_bin, [listen, "PIPE"], slog)
    try:
        wait_tcp(port)
        openssl_bin = os.environ.get("SOCAT_BENCH_OPENSSL_BIN", "")
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
    run_dir: Path,
    benchclient: Path,
) -> dict[str, Any]:
    """Record the handshake each bench pairing actually negotiates."""
    out: dict[str, Any] = {}
    print("  probe go client / go TLS-LISTEN ...", flush=True)
    out["go_client_go_server"] = probe_go_client(
        server_bin=go_bin,
        proto="tls",
        certs=certs,
        run_dir=run_dir,
        benchclient=benchclient,
        tag="probe.go-go",
        impl="go",
    )
    print("  probe go client / go QUIC-LISTEN ...", flush=True)
    out["go_client_go_quic"] = probe_go_client(
        server_bin=go_bin,
        proto="quic",
        certs=certs,
        run_dir=run_dir,
        benchclient=benchclient,
        tag="probe.go-quic",
    )
    print("  probe go client / go DTLS-LISTEN ...", flush=True)
    out["go_client_go_dtls"] = probe_go_client(
        server_bin=go_bin,
        proto="dtls",
        certs=certs,
        run_dir=run_dir,
        benchclient=benchclient,
        tag="probe.go-dtls",
    )
    if classic_bin:
        if os.environ.get("SOCAT_BENCH_OPENSSL_BIN", ""):
            print("  probe openssl s_client / classic OPENSSL-LISTEN ...", flush=True)
            out["openssl_client_classic_server"] = probe_openssl_sclient(
                server_bin=classic_bin,
                certs=certs,
                run_dir=run_dir,
                tag="probe.ossl-classic",
            )
        else:
            out["openssl_client_classic_server"] = {
                "ok": False,
                "error": "openssl executable not found",
            }
        print("  probe go client / classic OPENSSL-LISTEN ...", flush=True)
        out["go_client_classic_server"] = probe_go_client(
            server_bin=classic_bin,
            proto="tls",
            certs=certs,
            run_dir=run_dir,
            benchclient=benchclient,
            tag="probe.go-classic",
            impl="classic",
        )
    return out


def collect_meta(args: dict[str, Any]) -> dict[str, Any]:
    go_bin = args["socat"]
    classic = args.get("classic")
    openssl_bin = os.environ.get("SOCAT_BENCH_OPENSSL_BIN", "")
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git": git_head(ROOT),
        "hostname": socket.gethostname(),
        "uname": f"{platform.system()} {platform.release()}",
        "cpu_model": cpu_model(),
        "nproc": os.cpu_count() or 0,
        "go_version": first_line(["go", "version"]),
        "go_socat": go_bin,
        "go_socat_version": socat_version([go_bin, "-V"]),
        "classic_socat": classic or "",
        "classic_socat_version": socat_version([classic, "-V"]) if classic else "",
        "openssl_bin": openssl_bin,
        "openssl_version": first_line([openssl_bin, "version"]) if openssl_bin else "",
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


def dir_allows_exec(directory: Path) -> bool:
    probe = directory / ".exec-probe"
    try:
        probe.write_bytes(b"")
        probe.chmod(0o700)
        return os.access(probe, os.X_OK)
    except OSError:
        return False
    finally:
        probe.unlink(missing_ok=True)


def linux_shm_root() -> Path | None:
    shm = Path("/dev/shm")
    if not (sys.platform.startswith("linux") and shm.is_dir() and os.access(shm, os.W_OK)):
        return None
    candidate = shm / f"socat-bench-{os.getuid()}"
    try:
        prepare_storage_root(candidate)
    except SystemExit:
        return None
    if not dir_allows_exec(candidate):
        return None
    return candidate


def benchmark_storage_root(workdir: Path) -> Path:
    return linux_shm_root() or workdir / "storage"


def prepare_storage_root(root: Path) -> None:
    if os.name == "nt":
        root.mkdir(parents=True, exist_ok=True)
    else:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink():
        raise SystemExit(f"benchmark storage must not be a symlink: {root}")
    if os.name != "nt":
        if root.stat().st_uid != os.getuid():
            raise SystemExit(f"benchmark storage is owned by another user: {root}")
        root.chmod(0o700)


def lock_file(f: BinaryIO) -> None:
    if os.name == "nt":
        f.seek(0, os.SEEK_END)
        if f.tell() == 0:
            f.write(b"\0")
            f.flush()
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)


def unlock_file(f: BinaryIO) -> None:
    if os.name == "nt":
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def remove_stale_runs(root: Path) -> None:
    for stale in root.glob("run-*"):
        if stale.is_symlink() or stale.is_file():
            stale.unlink(missing_ok=True)
        elif stale.is_dir():
            shutil.rmtree(stale)


def require_free_space(path: Path, needed: int) -> None:
    free = shutil.disk_usage(path).free
    if free >= needed:
        return
    raise SystemExit(
        f"benchmark needs {needed / MIB:.0f} MiB free on {path} but only "
        f"{free / MIB:.0f} MiB is available; reduce SOCAT_BENCH_SIZE or free space"
    )


def payload_budget(size: int, buffer: int, wanted: tuple[str, ...]) -> int:
    needed = size
    sink = size
    for case in set(wanted) & DATAGRAM_CASES:
        frame_size = datagram_buffer(case, buffer)
        framed_size = datagram_frame_count(size, frame_size) * frame_size
        needed += framed_size
        sink = max(sink, framed_size)
    if any(case in STREAM_CASES or case in DATAGRAM_CASES for case in wanted):
        needed += sink
    return needed + STORAGE_RESERVE


@contextmanager
def run_session(workdir: Path, needed: int) -> Iterator[Path]:
    """Locked per-user root; scratch files live in a fresh run-* directory."""
    root = benchmark_storage_root(workdir)
    prepare_storage_root(root)
    with (root / ".lock").open("a+b") as lock:
        lock_file(lock)
        tmp: tempfile.TemporaryDirectory[str] | None = None
        try:
            remove_stale_runs(root)
            kwargs: dict[str, Any] = {"prefix": "run-", "dir": str(root)}
            try:
                tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True, **kwargs)
            except TypeError:
                tmp = tempfile.TemporaryDirectory(**kwargs)
            run_dir = Path(tmp.name)
            require_free_space(run_dir, needed)
            yield run_dir
        finally:
            if tmp is not None:
                tmp.cleanup()
            unlock_file(lock)


def datagram_buffer(case: str, buffer: int) -> int:
    return min(buffer, DTLS_FRAME_SIZE) if case == "dtls" else buffer


def datagram_frame_count(size: int, buffer: int) -> int:
    if size <= 0:
        raise ValueError("SOCAT_BENCH_SIZE must be positive")
    if buffer <= DATAGRAM_HEADER.size:
        raise ValueError(
            f"SOCAT_BENCH_BUFFER must exceed the {DATAGRAM_HEADER.size}-byte frame header"
        )
    if buffer > DATAGRAM_MAX_SIZE:
        raise ValueError(f"SOCAT_BENCH_BUFFER must not exceed {DATAGRAM_MAX_SIZE}")
    payload_per_frame = buffer - DATAGRAM_HEADER.size
    return (size + payload_per_frame - 1) // payload_per_frame


def write_datagram_payload(src: Path, dest: Path, size: int, buffer: int) -> tuple[int, int]:
    """Frame source bytes into dest. Returns (frame_count, wire_size)."""
    frame_count = datagram_frame_count(size, buffer)
    wire_size = frame_count * buffer
    payload_per_frame = buffer - DATAGRAM_HEADER.size
    written = 0
    with src.open("rb") as source, dest.open("wb") as out:
        for sequence in range(frame_count):
            payload_len = min(payload_per_frame, size - written)
            data = source.read(payload_len)
            if len(data) != payload_len:
                dest.unlink(missing_ok=True)
                raise ValueError(f"datagram payload ended after {written + len(data)} bytes; want {size}")
            out.write(DATAGRAM_HEADER.pack(DATAGRAM_MAGIC, sequence, payload_len, zlib.crc32(data)))
            out.write(data)
            out.write(b"\x00" * (payload_per_frame - payload_len))
            written += payload_len
    if written != size or dest.stat().st_size != wire_size:
        dest.unlink(missing_ok=True)
        raise ValueError(f"failed to frame {size} datagram payload bytes")
    return frame_count, wire_size


def prepare_payload(
    run_dir: Path,
    size: int,
    buffer: int,
    wanted: tuple[str, ...],
    benchclient: Path,
) -> tuple[Path, str, dict[str, Path]]:
    dest = run_dir / "payload"
    given = os.environ.get("SOCAT_BENCH_PAYLOAD", "").strip()
    if given:
        src = Path(given)
        if not src.is_file():
            raise SystemExit(f"SOCAT_BENCH_PAYLOAD is not a file: {src}")
        st = src.stat().st_size
        if st < size:
            raise SystemExit(
                f"SOCAT_BENCH_PAYLOAD {src} is {st} bytes; need at least {size}. "
                "Do not use /dev/zero (compressible)."
            )
        copy_prefix(src, dest, size)
        note = f"file:{src}"
    else:
        generate_aes_ctr(benchclient, dest, size)
        note = "aes-128-ctr (incompressible)"

    framed: dict[str, Path] = {}
    for case in sorted(set(wanted) & DATAGRAM_CASES):
        framed[case] = run_dir / f"payload.{case}"
        write_datagram_payload(dest, framed[case], size, datagram_buffer(case, buffer))
    return dest, note, framed


def analyze_datagram_sink(sink: Path, size: int, buffer: int) -> dict[str, Any]:
    """Validate fixed-size frames and report datagram delivery properties."""
    expected = datagram_frame_count(size, buffer)
    payload_per_frame = buffer - DATAGRAM_HEADER.size
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
                magic, sequence, payload_len, checksum = DATAGRAM_HEADER.unpack_from(frame)
                expected_len = 0
                if sequence < expected:
                    expected_len = min(payload_per_frame, size - sequence * payload_per_frame)
                data = frame[DATAGRAM_HEADER.size : DATAGRAM_HEADER.size + payload_len]
                if (
                    magic != DATAGRAM_MAGIC
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
    with src.open("rb") as inf, dest.open("wb") as out:
        left = size
        while left > 0:
            chunk = inf.read(min(1024 * 1024, left))
            if not chunk:
                break
            out.write(chunk)
            left -= len(chunk)
    if dest.stat().st_size != size:
        dest.unlink(missing_ok=True)
        raise SystemExit(f"failed to copy {size} bytes from {src}")


def generate_aes_ctr(benchclient: Path, dest: Path, size: int) -> None:
    run_checked(
        [str(benchclient), "-mode", "payload", "-out", str(dest), "-size", str(size)],
        quiet=True,
    )
    if not dest.is_file() or dest.stat().st_size != size:
        dest.unlink(missing_ok=True)
        raise SystemExit(f"payload generate wrote the wrong size: {dest}")


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
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


def wait_unix(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(f"UNIX socket {path} did not appear")


def read_rss_kib(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/status", encoding="ascii", errors="ignore") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


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


def tree_rss_kib(pids: list[int]) -> int | None:
    total = 0
    measured = False
    found: set[int] = set()
    for p in pids:
        if p <= 0:
            continue
        found |= descendant_pids(p)
    for pid in found:
        rss = read_rss_kib(pid)
        if rss is not None:
            total += rss
            measured = True
    return total if measured else None


def rss_available() -> bool:
    return sys.platform.startswith("linux") and Path("/proc/self/status").is_file()


class RSSSampler:
    def __init__(self, pids: list[int], interval: float = 0.05) -> None:
        self.pids = pids
        self.interval = interval
        self.peak: int | None = None
        self._stop = threading.Event()
        self._th = (
            threading.Thread(target=self._run, name="rss-sample", daemon=True)
            if rss_available()
            else None
        )

    def start(self) -> None:
        if self._th is not None:
            self._th.start()

    def stop(self) -> int | None:
        if self._th is None:
            return None
        self._stop.set()
        self._th.join(timeout=2)
        return self.peak

    def _run(self) -> None:
        while not self._stop.is_set():
            rss = tree_rss_kib(self.pids)
            if rss is not None and (self.peak is None or rss > self.peak):
                self.peak = rss
            self._stop.wait(self.interval)


def start_socat(
    bin_path: str, extra: list[str], log: Path, *, buffer: int | None = None
) -> subprocess.Popen:
    args = [
        bin_path,
        "-b",
        str(buffer) if buffer is not None else os.environ.get("SOCAT_BENCH_BUFFER", "8192"),
        "-t",
        "2",
        "-T",
        "60",
        *extra,
    ]
    log.parent.mkdir(parents=True, exist_ok=True)
    fh = log.open("w", encoding="utf-8")
    try:
        if os.name == "nt":
            process_group: dict[str, Any] = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            process_group = {"start_new_session": True}
        return subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=fh,
            stderr=fh,
            **process_group,
        )
    finally:
        fh.close()


def kill_proc(p: subprocess.Popen | None) -> None:
    if p is None or p.poll() is not None:
        return
    if os.name == "nt":
        try:
            p.terminate()
        except OSError:
            return
    else:
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
        if os.name == "nt":
            p.kill()
        else:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                p.kill()
        p.wait(timeout=2)


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
    if case == "ws":
        return (
            f"WS-LISTEN:{port},reuseaddr,bind=127.0.0.1",
            f"WS:127.0.0.1:{port}",
        )
    if case == "wss":
        return (
            f"WSS-LISTEN:{port},reuseaddr,bind=127.0.0.1,cert={crt},key={key},verify=0",
            f"WSS:127.0.0.1:{port},verify=1,cafile={ca},commonname=localhost",
        )
    if case == "quic":
        return (
            f"QUIC-LISTEN:{port},reuseaddr,bind=127.0.0.1,cert={crt},key={key},verify=0",
            f"QUIC:127.0.0.1:{port},verify=1,cafile={ca},commonname=localhost",
        )
    if case == "dtls":
        return (
            f"DTLS-LISTEN:{port},reuseaddr,bind=127.0.0.1,cert={crt},key={key},verify=0",
            f"DTLS:127.0.0.1:{port},verify=1,cafile={ca},commonname=localhost",
        )
    if case == "udp":
        # RECV+SENDTO: a stream of datagrams. Non-fork *-LISTEN is one-shot
        # (first packet then EOF) on this port; classic LISTEN stays connected.
        return (
            f"UDP4-RECV:{port},reuseaddr,bind=127.0.0.1,rcvbuf=8388608,sndbuf=8388608",
            f"UDP4-SENDTO:127.0.0.1:{port},sndbuf=8388608,rcvbuf=8388608",
        )
    raise ValueError(case)


def listen_wait(case: str, port: int, sock: Path) -> None:
    if case == "unix":
        wait_unix(sock)
    elif case in {"quic", "udp", "dtls"}:
        wait_udp(port)
    else:
        wait_tcp(port)


def wait_file_quiet(
    path: Path, timeout: float = 10.0, quiet: float = DATAGRAM_QUIET_SECONDS
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


def run_datagram_once(
    *,
    case: str,
    bin_path: str,
    framed_payload: Path,
    size: int,
    buffer: int,
    certs: dict[str, Path],
    run_dir: Path,
    tag: str,
) -> dict[str, Any]:
    if case not in DATAGRAM_CASES:
        raise ValueError(case)
    wire_size = framed_payload.stat().st_size
    port = free_udp_port()
    sock = run_dir / f"{tag}.sock"
    sink = run_dir / f"sink.{tag}"
    sink.unlink(missing_ok=True)
    listen, connect = stream_addrs(case, port, sock, certs)
    slog = run_dir / "logs" / f"{tag}.server.log"
    clog = run_dir / "logs" / f"{tag}.client.log"
    server = start_socat(
        bin_path, ["-u", listen, f"OPEN:{sink},creat,trunc,wronly"], slog, buffer=buffer
    )
    sampler: RSSSampler | None = None
    label = case.upper()
    try:
        listen_wait(case, port, sock)
        sampler = RSSSampler([server.pid])
        sampler.start()
        t0 = time.perf_counter()
        client = start_socat(
            bin_path, ["-u", f"OPEN:{framed_payload},rdonly", connect], clog, buffer=buffer
        )
        sampler.pids.append(client.pid)
        try:
            rc = client.wait(timeout=120)
        except subprocess.TimeoutExpired:
            kill_proc(client)
            raise TimeoutError(f"{label} client socat timed out") from None
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

        delivery = analyze_datagram_sink(sink, size, buffer)
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
            "frame_bytes": buffer,
            **delivery,
        }
        if delivery["unique_datagrams"] == 0:
            result["status"] = "fail"
            result["detail"] = f"no valid {label} datagrams reached the sink"
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
    run_dir: Path,
    tag: str,
) -> dict[str, Any]:
    port = free_tcp_port()
    sock = run_dir / f"{tag}.sock"
    sink = run_dir / f"sink.{tag}"
    sink.unlink(missing_ok=True)
    if sock.exists():
        sock.unlink()
    listen, connect = stream_addrs(case, port, sock, certs, impl=impl)
    slog = run_dir / "logs" / f"{tag}.server.log"
    clog = run_dir / "logs" / f"{tag}.client.log"
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
        server_timed_out = False
        try:
            server_rc = server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server_timed_out = True
            kill_proc(server)
            server_rc = server.returncode
        elapsed = time.perf_counter() - t0
        peak = sampler.stop()
        if rc != 0:
            return {
                "status": "fail",
                "detail": f"client exit {rc}: {clog.read_text(encoding='utf-8', errors='replace')[-400:]}",
            }
        if server_timed_out:
            return {
                "status": "fail",
                "detail": "server socat timed out before completing the sink",
                "elapsed_s": elapsed,
                "peak_rss_kib": peak,
            }
        if server_rc != 0:
            return {
                "status": "fail",
                "detail": f"server exit {server_rc}: {slog.read_text(encoding='utf-8', errors='replace')[-400:]}",
                "elapsed_s": elapsed,
                "peak_rss_kib": peak,
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
    if case in {"dtls", "dtls-rr", "dtls-hs"}:
        return (
            f"DTLS-LISTEN:{port},reuseaddr,bind=127.0.0.1{fork_opt},"
            f"cert={crt},key={key},verify=0"
        )
    raise ValueError(case)


def proto_of(case: str) -> str:
    if case.startswith("dtls"):
        return "dtls"
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
    run_dir: Path,
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
    slog = run_dir / "logs" / f"{tag}.server.log"
    server = start_socat(bin_path, [listen, "PIPE"], slog)
    try:
        if proto_of(case) in UDP_PROTOS:
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


def last_failure_detail(runs: list[dict[str, Any]]) -> str:
    for run in reversed(runs):
        if run.get("status") != "ok" and run.get("detail"):
            return str(run["detail"])
    return "all runs failed" if runs else "no runs"


def peak_rss_kib(runs: list[dict[str, Any]]) -> int | None:
    values = [r.get("peak_rss_kib") for r in runs]
    measured = [int(value) for value in values if value is not None]
    return max(measured) if measured else None


def rss_text(value: int | None) -> str:
    return "n/a" if value is None else f"{value} KiB"


def rss_value(value: int | None) -> str:
    return "n/a" if value is None else str(value)


def summarize_stream(runs: list[dict[str, Any]]) -> dict[str, Any]:
    oks = [r for r in runs if r.get("status") == "ok"]
    if not oks:
        return {
            "status": "fail",
            "detail": last_failure_detail(runs),
        }
    mibs = [float(r["mib_s"]) for r in oks]
    elapsed = [float(r["elapsed_s"]) for r in oks]
    return {
        "status": "ok" if len(oks) == len(runs) else "fail",
        "kind": "stream",
        "mib_s": {"median": median(mibs), "min": min(mibs), "max": max(mibs), "runs": mibs},
        "elapsed_s": {"median": median(elapsed), "min": min(elapsed), "max": max(elapsed)},
        "peak_rss_kib": peak_rss_kib(oks),
        "ok_runs": len(oks),
        "n_runs": len(runs),
        "detail": "" if len(oks) == len(runs) else last_failure_detail(runs),
    }


def summarize_datagram(runs: list[dict[str, Any]]) -> dict[str, Any]:
    oks = [r for r in runs if r.get("status") == "ok"]
    if not oks:
        return {
            "status": "fail",
            "detail": last_failure_detail(runs),
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
        "frame_bytes": int(oks[0]["frame_bytes"]),
        "send_mib_s": rates("send_mib_s"),
        "receive_mib_s": rates("receive_mib_s"),
        "loss_pct": rates("loss_pct"),
        "duplicate_datagrams": counts("duplicate_datagrams"),
        "reordered_datagrams": counts("reordered_datagrams"),
        "corrupt_datagrams": counts("corrupt_datagrams"),
        "expected_datagrams": int(oks[0]["expected_datagrams"]),
        "peak_rss_kib": peak_rss_kib(oks),
        "ok_runs": len(oks),
        "n_runs": len(runs),
        "detail": "" if len(oks) == len(runs) else last_failure_detail(runs),
    }


def summarize_rr(runs: list[dict[str, Any]]) -> dict[str, Any]:
    oks = [r for r in runs if r.get("status") == "ok"]
    if not oks:
        return {
            "status": "fail",
            "detail": last_failure_detail(runs),
        }
    med = [float(r["rtt_us"]["median"]) for r in oks]
    p99 = [float(r["rtt_us"]["p99"]) for r in oks]
    rate = [float(r["msgs_s"]) for r in oks]
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
        "peak_rss_kib": peak_rss_kib(oks),
        "ok_runs": len(oks),
        "n_runs": len(runs),
        "detail": "" if len(oks) == len(runs) else last_failure_detail(runs),
    }


def summarize_hs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    oks = [r for r in runs if r.get("status") == "ok"]
    if not oks:
        return {
            "status": "fail",
            "detail": last_failure_detail(runs),
        }
    rate = [float(r["hs_s"]) for r in oks]
    return {
        "status": "ok" if len(oks) == len(runs) else "fail",
        "kind": "hs",
        "hs_s": {"median": median(rate), "min": min(rate), "max": max(rate), "runs": rate},
        "peak_rss_kib": peak_rss_kib(oks),
        "ok_runs": len(oks),
        "n_runs": len(runs),
        "detail": "" if len(oks) == len(runs) else last_failure_detail(runs),
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
        f"go_socat_version={m.get('go_socat_version')}",
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
                f"peak_rss_kib={rss_value(c['peak_rss_kib'])}"
            )
        elif c.get("kind") == "datagram":
            send = c["send_mib_s"]
            receive = c["receive_mib_s"]
            loss = c["loss_pct"]
            lines.append(
                f"{ident}: send={send['median']:.1f} MiB/s "
                f"receive={receive['median']:.1f} MiB/s "
                f"loss={loss['median']:.3f}% "
                f"frame_bytes={c.get('frame_bytes', 'n/a')} "
                f"duplicate={c['duplicate_datagrams']['total']} "
                f"reordered={c['reordered_datagrams']['total']} "
                f"corrupt={c['corrupt_datagrams']['total']} "
                f"peak_rss_kib={rss_value(c['peak_rss_kib'])}"
            )
        elif c.get("kind") == "rr":
            r = c["rtt_us"]
            lines.append(
                f"{ident}: rtt_us median={r['median']:.1f} p99={r['p99']:.1f} "
                f"msgs_s={c['msgs_s']['median']:.0f} "
                f"peak_rss_kib={rss_value(c['peak_rss_kib'])}"
            )
        elif c.get("kind") == "hs":
            h = c["hs_s"]
            lines.append(
                f"{ident}: {h['median']:.1f} hs/s "
                f"(min {h['min']:.1f} max {h['max']:.1f}) "
                f"peak_rss_kib={rss_value(c['peak_rss_kib'])}"
            )
        else:
            lines.append(f"{ident}: {st}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def publish_results(doc: dict[str, Any], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    write_summary(doc, dest.with_suffix(".summary.txt"))


def _exit_on_sigterm(signum: int, _frame: object) -> None:
    raise SystemExit(128 + signum)


def main() -> int:
    os.chdir(ROOT)
    if os.name != "nt":
        signal.signal(signal.SIGTERM, _exit_on_sigterm)
    workdir = Path(os.environ.get("SOCAT_BENCH_WORKDIR", str(ROOT / "testdata/tmp/bench")))
    size = parse_size(os.environ.get("SOCAT_BENCH_SIZE", "256M"))
    buffer = int(os.environ.get("SOCAT_BENCH_BUFFER", "8192"))
    probe_only = os.environ.get("SOCAT_BENCH_PROBE_ONLY", "") == "1"
    wanted = tuple(sys.argv[1:] or (() if probe_only else DEFAULT_CASES))
    needed = 0 if probe_only else payload_budget(size, buffer, wanted)
    with run_session(workdir, needed) as run_dir:
        setup_benchmark(run_dir)
        return run_benchmark(run_dir, workdir, size, buffer, wanted, probe_only)


def run_benchmark(
    run_dir: Path,
    workdir: Path,
    size: int,
    buffer: int,
    wanted: tuple[str, ...],
    probe_only: bool,
) -> int:
    runs = int(os.environ.get("SOCAT_BENCH_RUNS", "5"))
    warmup = int(os.environ.get("SOCAT_BENCH_WARMUP", "1"))
    socat = os.environ.get("SOCAT_BIN", str(ROOT / "socat"))
    classic = os.environ.get("SOCAT_CLASSIC_BIN", "").strip()
    benchclient = Path(os.environ.get("SOCAT_BENCH_CLIENT_BIN", str(run_dir / "benchclient")))
    certs = {
        "ca": Path(os.environ["SOCAT_BENCH_CA"]),
        "crt": Path(os.environ["SOCAT_BENCH_CERT"]),
        "key": Path(os.environ["SOCAT_BENCH_KEY"]),
    }
    for c in wanted:
        if c not in STREAM_CASES | DATAGRAM_CASES | RR_CASES | HS_CASES:
            raise SystemExit(f"unknown case {c}; want {', '.join(DEFAULT_CASES)}")

    if probe_only:
        print("probe TLS/QUIC/DTLS handshakes (no timed cases)", flush=True)
        tls = probe_all(
            go_bin=socat,
            classic_bin=classic or None,
            certs=certs,
            run_dir=run_dir,
            benchclient=benchclient,
        )
        print(json.dumps(tls, indent=2), flush=True)
        save = os.environ.get("SOCAT_BENCH_SAVE_BASELINE", "").strip()
        if save and Path(save).is_file():
            doc = json.loads(Path(save).read_text(encoding="utf-8"))
            doc.setdefault("meta", {})["tls"] = tls
            publish_results(doc, Path(save))
            print(f"updated tls probe in {save}", flush=True)
        return 0 if all(v.get("ok") for v in tls.values() if isinstance(v, dict)) else 1

    payload, payload_note, framed_payloads = prepare_payload(
        run_dir, size, buffer, wanted, benchclient
    )
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
    print("probe TLS/QUIC/DTLS handshakes ...", flush=True)
    doc["meta"]["tls"] = probe_all(
        go_bin=socat,
        classic_bin=classic or None,
        certs=certs,
        run_dir=run_dir,
        benchclient=benchclient,
    )

    impls_for = []
    if classic:
        impls_for.append(("classic", classic))
    impls_for.append(("go", socat))

    rr_n = int(os.environ.get("SOCAT_BENCH_RR_N", "20000"))
    rr_warmup = int(os.environ.get("SOCAT_BENCH_RR_WARMUP", "1000"))
    rr_size = int(os.environ.get("SOCAT_BENCH_RR_SIZE", "64"))
    hs_n = int(os.environ.get("SOCAT_BENCH_HS_N", "200"))
    hs_warmup = int(os.environ.get("SOCAT_BENCH_HS_WARMUP", "20"))

    print(
        f"payload={payload} ({payload_note}, {size} bytes)\n"
        f"go={socat}\nclassic={classic or '<none>'}\n"
        f"cases={','.join(wanted)} runs={runs} warmup={warmup}",
        flush=True,
    )

    for case in wanted:
        for impl, bin_path in impls_for:
            if case in GO_ONLY and impl != "go":
                protocol = GO_ONLY[case]
                doc["cases"].append(
                    {
                        "id": case,
                        "impl": impl,
                        "status": "skip",
                        "detail": f"{protocol} is not available in classic",
                    }
                )
                print(f"  skip {case}/{impl} ({protocol} is not available in classic)", flush=True)
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
                            run_dir=run_dir,
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
                                run_dir=run_dir,
                                tag=f"{case}.{impl}.{i}",
                            )
                        )
                    summary = summarize_stream(samples)
                elif case in DATAGRAM_CASES:
                    frame_size = datagram_buffer(case, buffer)
                    for i in range(warmup):
                        run_datagram_once(
                            case=case,
                            bin_path=bin_path,
                            framed_payload=framed_payloads[case],
                            size=size,
                            buffer=frame_size,
                            certs=certs,
                            run_dir=run_dir,
                            tag=f"{case}.{impl}.warmup{i}",
                        )
                    for i in range(runs):
                        samples.append(
                            run_datagram_once(
                                case=case,
                                bin_path=bin_path,
                                framed_payload=framed_payloads[case],
                                size=size,
                                buffer=frame_size,
                                certs=certs,
                                run_dir=run_dir,
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
                            run_dir=run_dir,
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
                                run_dir=run_dir,
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
                            run_dir=run_dir,
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
                                run_dir=run_dir,
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
                    f"rss={rss_text(row['peak_rss_kib'])}",
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
                    f"rss={rss_text(row['peak_rss_kib'])}",
                    flush=True,
                )
            elif row.get("status") == "ok" and row.get("kind") == "rr":
                print(
                    f"       rtt={row['rtt_us']['median']:.1f} µs  "
                    f"p99={row['rtt_us']['p99']:.1f}  "
                    f"rss={rss_text(row['peak_rss_kib'])}",
                    flush=True,
                )
            elif row.get("status") == "ok" and row.get("kind") == "hs":
                print(
                    f"       {row['hs_s']['median']:.1f} hs/s  "
                    f"rss={rss_text(row['peak_rss_kib'])}",
                    flush=True,
                )
            else:
                print(f"       {row.get('status')} {row.get('detail', '')}", flush=True)

    scratch = run_dir / "results.json"
    publish_results(doc, scratch)
    out_json = Path(os.environ.get("SOCAT_BENCH_OUT", str(workdir / "results.json")))
    if out_json.resolve() != scratch.resolve():
        publish_results(doc, out_json)
    save = os.environ.get("SOCAT_BENCH_SAVE_BASELINE", "").strip()
    if save:
        dest = Path(save)
        if dest.resolve() != scratch.resolve() and dest.resolve() != out_json.resolve():
            publish_results(doc, dest)
        print(f"saved baseline {dest}", flush=True)
    print(f"wrote {out_json}", flush=True)
    print(f"wrote {out_json.with_suffix('.summary.txt')}", flush=True)

    failed = [c for c in doc["cases"] if c.get("status") == "fail"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
