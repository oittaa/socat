#!/usr/bin/env python3
"""Build pinned DTLS 1.3 reference tools in an isolated Linux lab directory."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


SCRIPT_DIR = Path(__file__).resolve().parent


def run(args, *, cwd=None, log=None, env=None):
    if log is None:
        return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()
    print(f"Building in {cwd}; log: {log}", flush=True)
    with log.open("a") as output:
        subprocess.run(
            args, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT,
            check=True,
        )


def checkout(root, name, source):
    path = root / "src" / name
    commit = source["commit"]
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError(f"invalid pinned commit for {name}")
    if not path.exists():
        path.mkdir(parents=True)
        run(["git", "init", "--quiet", str(path)])
        run(["git", "remote", "add", "origin", source["repository"]], cwd=path)
    if run(["git", "remote", "get-url", "origin"], cwd=path) != source["repository"]:
        raise ValueError(f"unexpected remote in {path}")
    if run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=path):
        raise ValueError(f"tracked source changes in {path}; use another --root")
    run(["git", "fetch", "--depth", "1", "origin", commit], cwd=path)
    run(["git", "checkout", "--quiet", "--detach", commit], cwd=path)
    if run(["git", "rev-parse", "HEAD"], cwd=path) != commit:
        raise ValueError(f"unexpected source revision in {path}")
    return path


def build(root, name, sources, jobs):
    source = checkout(root, name, sources[name])
    destination = root / "build" / name
    destination.mkdir(parents=True, exist_ok=True)
    log = root / "logs" / f"{name}.log"
    env = os.environ.copy()
    env["PATH"] = "/usr/local/go/bin:" + env.get("PATH", "")

    def command(*args, cwd=destination):
        run(list(args), cwd=cwd, log=log, env=env)

    if name == "openssl":
        prefix = root / "install" / "openssl"
        command(str(source / "Configure"), "no-shared", "no-tests",
                f"--prefix={prefix}", "--libdir=lib")
        command("make", f"-j{jobs}")
        command("make", "install_sw")
        binary = prefix / "bin" / "openssl"
        help_result = subprocess.run(
            [str(binary), "s_client", "-help"], capture_output=True, text=True,
            check=False,
        )
        if "-dtls1_3" not in help_result.stderr + help_result.stdout:
            raise RuntimeError("reference OpenSSL does not support -dtls1_3")
        return {"openssl": str(binary), "version": run([str(binary), "version"])}
    if name == "wolfssl":
        # Large stateless ClientHellos must fit the reference's receive buffer.
        command("cmake", "-S", str(source), "-B", str(destination), "-GNinja",
                "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=OFF",
                "-DWOLFSSL_DTLS=YES", "-DWOLFSSL_DTLS13=YES",
                "-DWOLFSSL_DTLS_CID=YES", "-DWOLFSSL_EXAMPLES=YES",
                "-DWOLFSSL_CURVE25519=YES",
                "-DCMAKE_C_FLAGS=-DWOLFSSL_DTLS_MTU_ADDITIONAL_READ_BUFFER=4096",
                "-DWOLFSSL_CRYPT_TESTS=NO")
        command("cmake", "--build", str(destination), "--parallel", str(jobs))
        return {
            "client": str(destination / "examples" / "client" / "client"),
            "server": str(destination / "examples" / "server" / "server"),
            "certificates": str(source / "certs"),
        }
    if name == "boringssl":
        command("cmake", "-S", str(source), "-B", str(destination), "-GNinja",
                "-DCMAKE_BUILD_TYPE=Release")
        command("cmake", "--build", str(destination), "--parallel", str(jobs),
                "--target", "bssl_shim")
        return {"shim": str(destination / "ssl" / "test" / "bssl_shim")}
    if name == "pion":
        helper = source / "cmd" / "socat-dtls13-oracle"
        helper.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SCRIPT_DIR.parent / "internal" / "dtls13" / "testdata" / "pion_oracle.go",
                        helper / "main.go")
        binary = destination / "pion-oracle"
        command("go", "build", "-o", str(binary), "./cmd/socat-dtls13-oracle", cwd=source)
        return {"server": str(binary)}
    if name == "classic":
        prefix = root / "install" / "openssl"
        if not (prefix / "bin" / "openssl").exists():
            raise RuntimeError("build the pinned OpenSSL reference first")
        if not (source / "configure").exists():
            command("autoconf", cwd=source)
        if (destination / "Makefile").exists():
            command("make", "clean")
        env["CPPFLAGS"] = f"-I{prefix / 'include'}"
        env["LDFLAGS"] = f"-L{prefix / 'lib'}"
        command(str(source / "configure"))
        command("make", f"-j{jobs}")
        binary = destination / "socat"
        linkage = run(["ldd", str(binary)])
        if "libssl.so" in linkage or "libcrypto.so" in linkage:
            raise RuntimeError("classic socat linked system OpenSSL instead of the pinned static build")
        return {"socat": str(binary), "openssl_linkage": "pinned static libraries"}
    raise ValueError(f"unknown reference {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "socat-dtls13-lab")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--only", choices=["openssl", "wolfssl", "boringssl", "pion", "classic"])
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run this reference builder inside the Linux lab")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    missing = [tool for tool in ("git", "cmake", "ninja", "make", "gcc", "g++", "perl", "autoconf", "ldd")
               if shutil.which(tool) is None]
    if missing:
        parser.error("missing build tools: " + ", ".join(missing))
    sources = json.loads((SCRIPT_DIR / "dtls13-baseline.json").read_text())
    classic = json.loads((SCRIPT_DIR / "classic-baseline.json").read_text())
    sources["classic"] = {
        "repository": classic["repository"], "commit": classic["release_commit"],
    }
    root = args.root.resolve()
    (root / "logs").mkdir(parents=True, exist_ok=True)
    manifest = root / "tools.json"
    outputs = json.loads(manifest.read_text()) if manifest.exists() else {}
    def publish():
        temporary = manifest.with_suffix(".tmp")
        temporary.write_text(json.dumps(outputs, indent=2) + "\n")
        temporary.replace(manifest)

    for name in [args.only] if args.only else ["openssl", "wolfssl", "boringssl", "pion"]:
        # A failed rebuild must not leave an older binary marked as ready.
        outputs.pop(name, None)
        publish()
        outputs[name] = {**build(root, name, sources, args.jobs), **sources[name]}
        publish()
        print(f"Ready: {name} at {sources[name]['commit']}", flush=True)
    print(f"Reference tool paths: {manifest}")


if __name__ == "__main__":
    main()
