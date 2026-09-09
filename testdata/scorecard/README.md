# Scorecard baselines

Classic `test.sh` results. Working logs go under gitignored `.scorecard/`.

From `classic-docker-baseline.summary.txt` and
`go-docker-baseline.summary.txt`:

| Label | OK | FAILED | CANT |
|-------|-----|--------|------|
| classic 1.8.1.3 (Docker, root) | 565 | 3 | 37 |
| go (this tree, Docker, root, privileged, `--internet`) | 541 | 9 | 55 |

Vs classic Docker, Go has 541 OK against 565
classic OK (`parity_gap_total` 24 in `go-vs-classic-docker-gaps.json`).

Names and per-test status are in those JSON files. DTLS:
[docs/dtls13.md](../../docs/dtls13.md#validation).

## Refresh

On a Linux Docker host:

```bash
make update-scorecard
```

That runs classic C and this tree as root (`MODE=classic`, `PRIVILEGED=1`,
`--internet`) and copies complete results here. It does not commit.

Official classic source pins: `scripts/classic-baseline.json`.

## Files

| File | Role |
|------|------|
| `classic-docker-baseline.json` | Classic C in Docker as root |
| `go-docker-baseline.json` | Go Docker/root run |
| `go-vs-classic-docker-gaps.json` | Classic-docker OK that Go did not get |
| `classic-docker-vs-host.json` | Host OK set vs docker |
| `classic-baseline.json` | Classic C host run |
| `go-baseline.json` | Go host run |
