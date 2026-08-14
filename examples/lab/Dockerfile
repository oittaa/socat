# Lab image: our socat + small real apps (curl, python http.server, microsocks).
# Build from the repo root:
#   docker build -t socat-lab -f examples/lab/Dockerfile .

FROM golang:1.26 AS gobuild
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/socat ./cmd/socat

FROM ubuntu:26.04 AS microsocks
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gcc libc6-dev make \
    && curl -fsSL https://github.com/rofl0r/microsocks/archive/refs/tags/v1.0.5.tar.gz \
        | tar -xz -C /tmp \
    && make -C /tmp/microsocks-1.0.5 \
    && cp /tmp/microsocks-1.0.5/microsocks /microsocks \
    && rm -rf /var/lib/apt/lists/*

FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        iproute2 \
        openssl \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gobuild /out/socat /usr/local/bin/socat
COPY --from=microsocks /microsocks /usr/local/bin/microsocks
COPY examples/lab/scenarios /lab/scenarios
COPY examples/lab/certs/gen.sh /lab/certs/gen.sh
RUN chmod 755 /usr/local/bin/socat /usr/local/bin/microsocks \
        /lab/scenarios/*.sh /lab/certs/gen.sh

WORKDIR /lab
CMD ["/lab/scenarios/entry.sh"]
