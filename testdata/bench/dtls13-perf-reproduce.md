# Reproduce the DTLS library comparison

Run from the repository root on Linux with Go, Python 3, GCC/G++, Perl, Git,
make, autoconf, automake, libtool, CMake, Ninja and the OpenSSL CLI installed.
These commands use the x86-64 acceleration settings behind the [recorded results](dtls13-perf.md).
Adapt CPU flags for another architecture and record them with the results.
Sources, builds and outputs stay outside the repository.

Build the pinned OpenSSL/Pion peers and a separate accelerated wolfSSL:

```sh
LAB="$HOME/socat-dtls13-lab"
WORK="$(mktemp -d)"
WOLF="$WORK/wolfssl"
PERF="$PWD/internal/dtls13/testdata/perf"
python3 scripts/dtls13-lab.py --root "$LAB" --only openssl
python3 scripts/dtls13-lab.py --root "$LAB" --only pion
git clone https://github.com/wolfSSL/wolfssl.git "$WOLF"
git -C "$WOLF" checkout --detach d72f6d9e4e85ffcadfa0c737959dc26b8717947a
(cd "$WOLF" && ./autogen.sh &&
  ./configure --enable-dtls --enable-dtls13 --enable-dtls-mtu \
    --enable-curve25519 --enable-aesni --enable-intelasm \
    --disable-examples --disable-crypttests --disable-shared --enable-static CFLAGS=-O3 &&
  make -j4)
```

The measured wolfSSL build enables `WOLFSSL_AESNI` and `USE_INTEL_SPEEDUP`
in `wolfssl/options.h`; the interoperability CMake build did not. OpenSSL
uses its default assembly. Exact pins are in [dtls13-baseline.json](../../scripts/dtls13-baseline.json).

Build all five helpers and their certificate. The original socat helper must
use the original module, with the same comparison fixture copied into it:

```sh
mkdir -p "$WORK/certs" "$LAB/src/pion/cmd/socat-perf" "$WORK/original"
go build -o "$WORK/socat-perf" "$PERF/common.go" "$PERF/socat.go"
cp "$PERF/common.go" "$PERF/pion.go" "$LAB/src/pion/cmd/socat-perf/"
(cd "$LAB/src/pion" && go build -o "$WORK/pion-perf" ./cmd/socat-perf)
gcc -O3 -pthread -I"$LAB/install/openssl/include" "$PERF/reference.c" \
  "$LAB/install/openssl/lib/libssl.a" "$LAB/install/openssl/lib/libcrypto.a" \
  -ldl -o "$WORK/openssl-perf"
gcc -O3 -pthread -DUSE_WOLFSSL -I"$WOLF" "$PERF/reference.c" \
  "$WOLF/src/.libs/libwolfssl.a" -lm -o "$WORK/wolfssl-perf"
git archive c1d05da5c6f501db633a9cb74cc4fa753711ca2c > "$WORK/original.tar"
tar -xf "$WORK/original.tar" -C "$WORK/original"
mkdir -p "$WORK/original/internal/dtls13/testdata/perf"
cp "$PERF/common.go" "$PERF/socat.go" "$WORK/original/internal/dtls13/testdata/perf/"
(cd "$WORK/original" && go build -o "$WORK/socat-original-perf" \
  ./internal/dtls13/testdata/perf/common.go ./internal/dtls13/testdata/perf/socat.go)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$WORK/certs/key.pem" -out "$WORK/certs/cert.pem" -days 2 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1
python3 scripts/dtls13-perf.py --workdir "$WORK" --revision "$(git rev-parse HEAD)" \
  --output "$WORK/comparison.json"
```

The runner records the pinned OpenSSL long-transfer failure and exits nonzero
after completing the other cases. Keep its failure and the output JSON.
For CPU/allocation profiles, run the Go helpers separately with
`-cpu-profile` and `-mem-profile`; keep those runs out of the timed comparison.
