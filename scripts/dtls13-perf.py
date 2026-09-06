#!/usr/bin/env python3
"""Run prebuilt, pinned DTLS library helpers; see testdata/bench/dtls13-perf.md."""
import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--records", type=int, default=1048576)
    parser.add_argument("--roundtrips", type=int, default=50000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.samples, args.records, args.roundtrips) <= 0:
        parser.error("sample and operation counts must be positive")
    root = args.workdir.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    libraries = ["socat-original", "socat", "pion", "openssl", "wolfssl"]
    for library in libraries:
        if not (root / f"{library}-perf").is_file():
            parser.error(f"missing helper: {library}-perf")
    cert, key = str(root / "certs/cert.pem"), str(root / "certs/key.pem")
    baseline = json.loads((Path(__file__).parent / "dtls13-baseline.json").read_text())
    document = {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "revision": args.revision,
            "original_revision": "c1d05da5c6f501db633a9cb74cc4fa753711ca2c",
            "references": {name: baseline[name] for name in ("pion", "openssl", "wolfssl")},
            "platform": platform.platform(), "cpus": os.cpu_count(),
            "samples": args.samples, "handshake_timed": False,
            "warmup_roundtrips": 1000, "record_bytes": 1024,
            "socket_buffers": "OS defaults", "oneway_drain_ms": 250,
            "wolfssl_build": "-O3 --enable-dtls --enable-dtls13 --enable-dtls-mtu --enable-curve25519 --enable-aesni --enable-intelasm --disable-shared",
        },
        "runs": [],
    }
    for mode, count in (("rr", args.roundtrips), ("oneway", args.records)):
        for sample in range(args.samples):
            # Rotate order to reduce systematic first/last-run bias.
            order = libraries[sample % len(libraries):] + libraries[:sample % len(libraries)]
            for library in order:
                command = [str(root / f"{library}-perf")]
                if library in {"openssl", "wolfssl"}:
                    command += [cert, key, cert, mode, str(count), "1000"]
                else:
                    command += ["-cert", cert, "-key", key, "-ca", cert, "-mode", mode, "-n", str(count), "-warmup", "1000"]
                try:
                    result = subprocess.run(command, text=True, capture_output=True, timeout=180, check=True)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                    row = {"library": library, "sample": sample, "mode": mode, "n": count,
                           "error": str(error), "stderr": str(error.stderr)}
                    document["runs"].append(row)
                    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                    print(f"{mode} {library} sample {sample + 1}: FAILED {error.stderr}", flush=True)
                    continue
                row = json.loads(result.stdout)
                assert row["version"] == "DTLS 1.3" and row["frame_bytes"] == 1024
                assert row["cipher"] == "TLS_AES_128_GCM_SHA256" and row["group"] == "X25519"
                row.update(library=library, sample=sample, negotiation_log=result.stderr.strip())
                document["runs"].append(row)
                args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                print(f"{mode} {library} sample {sample + 1}: " + json.dumps(row), flush=True)
    document["summary"] = []
    for library in libraries:
        rows = [row for row in document["runs"] if row["library"] == library]
        summary = {"library": library, "failures": sum("error" in row for row in rows)}
        for metric in ("rtt_us", "send_mib_s", "receive_mib_s", "loss_pct"):
            values = [row[metric] for row in rows if metric in row]
            summary[metric] = {"median": statistics.median(values), "min": min(values), "max": max(values)} if values else None
        document["summary"].append(summary)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(document["summary"], indent=2), flush=True)
    return int(any(row["failures"] for row in document["summary"]))


if __name__ == "__main__":
    raise SystemExit(main())
