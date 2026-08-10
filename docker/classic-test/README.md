# Classic `test.sh` Docker runner

Ubuntu **26.04** image with classic **socat 1.8.1.3** built from upstream,
plus this repo’s scorecard scripts. Runs as **root** with network capabilities
so raw-IP, tcpwrap, TUN, and other privileged classic tests can pass.

## Build

```bash
docker build -t socat-classic-test -f docker/classic-test/Dockerfile .
```

## Run (preferred wrapper)

```bash
./scripts/docker-classic-scorecard.sh
```

Environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `MODE` | `classic` | `classic` / `stable` / `fast` |
| `ONLY` | empty | classic test.sh filter tokens |
| `OUT_HOST` | `.classic-scorecard-docker` | host path mounted at `/out` |
| `HOST_BASELINE` | `testdata/scorecard/classic-baseline.json` | verify host OK ⊆ docker OK |
| `NO_BUILD` | `0` | `1` = skip `docker build` |
| `PRIVILEGED` | `0` | `1` = `--privileged` instead of explicit caps |
| `ALLOW_LOST` | `216,304,410,453,492` | host-OK IDs allowed to fail in docker |
| `SCORECARD_EXIT` | `0` | `1` = exit non-zero if classic has FAILs |

## Direct `docker run`

```bash
docker run --rm \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  --cap-add=SYS_CHROOT --cap-add=SETUID --cap-add=SETGID \
  --cap-add=SYS_ADMIN --cap-add=NET_BIND_SERVICE \
  --device /dev/net/tun \
  -v "$PWD/.classic-scorecard-docker:/out" \
  -v "$PWD/testdata/scorecard/classic-baseline.json:/baseline/classic-baseline.json:ro" \
  -e HOST_BASELINE=/baseline/classic-baseline.json \
  -e MODE=classic \
  socat-classic-test
```

## Next: Go socat in the same image

Plan:

1. Multi-stage or second target that builds the Go binary into `/opt/go/socat`.
2. `LABEL=go SOCAT=/opt/go/socat` with the same `test.sh` and caps.
3. Compare against `classic-docker-baseline.json` (root-capable classic truth).

That path is the right place to implement features that need root (raw IP
ancillary, some interface tests, etc.).
