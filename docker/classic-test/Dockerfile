# Classic socat test.sh runner (root, full caps intended at runtime).
# Ubuntu 26.04 for a fixed, shareable scorecard environment.
#
# Build:
#   docker build -t socat-classic-test -f docker/classic-test/Dockerfile .
#
# Run (see scripts/docker-classic-scorecard.sh):
#   docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
#     --cap-add=SYS_CHROOT --cap-add=SETUID --cap-add=SETGID \
#     --device /dev/net/tun -v "$PWD/out:/out" socat-classic-test

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    CLASSIC_VERSION=1.8.1.3 \
    CLASSIC_PREFIX=/opt/classic

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        iproute2 \
        iputils-ping \
        net-tools \
        netcat-openbsd \
        openssl \
        python3 \
        procps \
        psmisc \
        util-linux \
        yodl \
        libssl-dev \
        libreadline-dev \
        libwrap0-dev \
        libsctp-dev \
        libtool \
        autoconf \
        automake \
        pkg-config \
        file \
        bash \
        grep \
        gawk \
        sed \
        coreutils \
        findutils \
        gzip \
        tar \
        xz-utils \
        linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/build
# Fetch from the Alpine distfiles mirror (valid TLS). dest-unreach.org serves a
# self-signed certificate, so it remains only a plain-HTTP fallback. The sha256
# is the one pinned by Homebrew homebrew-core (Formula/s/socat.rb) and was
# verified against both sources; bump it together with CLASSIC_VERSION.
RUN curl -fsSL -o "socat-${CLASSIC_VERSION}.tar.gz" \
        "https://distfiles.alpinelinux.org/distfiles/edge/socat-${CLASSIC_VERSION}.tar.gz" \
    || curl -fsSL -o "socat-${CLASSIC_VERSION}.tar.gz" \
        "http://www.dest-unreach.org/socat/download/socat-${CLASSIC_VERSION}.tar.gz" \
    && echo "06602ffd591e98c75b3dc1d66f0f19136cc666b0b2d95caad987d6ab2cb28097  socat-${CLASSIC_VERSION}.tar.gz" | sha256sum -c - \
    && tar -xzf "socat-${CLASSIC_VERSION}.tar.gz" \
    && cd "socat-${CLASSIC_VERSION}" \
    && ./configure --prefix="${CLASSIC_PREFIX}" \
    && make -j"$(nproc)" \
    && make install \
    && mkdir -p /opt/classic-src \
    && cp -a "/tmp/build/socat-${CLASSIC_VERSION}/." /opt/classic-src/ \
    && ln -sf "${CLASSIC_PREFIX}/bin/socat" /opt/classic-src/socat \
    && ln -sf "${CLASSIC_PREFIX}/bin/filan" /opt/classic-src/filan \
    && ln -sf "${CLASSIC_PREFIX}/bin/procan" /opt/classic-src/procan \
    && if [ -f /opt/classic-src/relsleep.c ] && [ ! -x /opt/classic-src/relsleep ]; then \
         cc -O2 -o /opt/classic-src/relsleep /opt/classic-src/relsleep.c; \
       fi \
    && rm -rf /tmp/build \
    && "${CLASSIC_PREFIX}/bin/socat" -V | head -40

WORKDIR /opt/scorecard
COPY scripts/classic-scorecard.sh scripts/classic-tunnet-guard.sh \
     scripts/scorecard-parse.py scripts/scorecard-compare.py \
     /opt/scorecard/scripts/
COPY docker/classic-test/entrypoint.sh /opt/scorecard/entrypoint.sh
RUN chmod +x /opt/scorecard/entrypoint.sh \
        /opt/scorecard/scripts/classic-scorecard.sh \
        /opt/scorecard/scripts/classic-tunnet-guard.sh \
    && mkdir -p /opt/scorecard/testdata/scorecard /out \
    && printf 'build:\n\t@true\n' > /opt/scorecard/Makefile

ENV SOCAT=${CLASSIC_PREFIX}/bin/socat \
    FILAN=${CLASSIC_PREFIX}/bin/filan \
    PROCAN=${CLASSIC_PREFIX}/bin/procan \
    CLASSIC_TEST_SH=/opt/classic-src/test.sh \
    OUT_DIR=/out \
    SKIP_BUILD=1 \
    LABEL=classic \
    MODE=classic

ENTRYPOINT ["/opt/scorecard/entrypoint.sh"]
CMD []
