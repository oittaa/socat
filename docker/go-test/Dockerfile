# Go socat scorecard image: classic test.sh + Go binaries, root/caps at runtime.
#
# Requires classic image already built (or build both via scripts/docker-go-scorecard.sh):
#   docker build -t socat-classic-test -f docker/classic-test/Dockerfile .
#   docker build -t socat-go-test -f docker/go-test/Dockerfile .
#
# Multi-stage: build Go binaries with official toolchain, layer onto classic test image.

# --- build Go socat / filan / procan ---
FROM golang:1.27 AS gobuild
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off: pure Go + x/sys; matches host make build without system libs.
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/socat ./cmd/socat \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/filan ./cmd/filan \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/procan ./cmd/procan

# --- classic test environment + Go under test ---
FROM socat-classic-test

COPY --from=gobuild /out/socat /out/filan /out/procan /opt/go/
RUN chmod 755 /opt/go/socat /opt/go/filan /opt/go/procan \
 && /opt/go/socat -V 2>&1 | head -5 || true

# Default to Go binary; classic remains at /opt/classic/bin/* and test.sh at /opt/classic-src.
ENV SOCAT=/opt/go/socat \
    FILAN=/opt/go/filan \
    PROCAN=/opt/go/procan \
    LABEL=go \
    SAVE_BASELINE=/out/go-docker-baseline.json

# Entrypoint inherited from socat-classic-test (scorecard + net prep).
