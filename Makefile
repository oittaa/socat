.PHONY: all build fmt fmt-check lint gosec test e2e test-netns-docker lab bench clean install hooks

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

GOFLAGS ?=
LDFLAGS ?= -s -w -X github.com/oittaa/socat.Version=$(VERSION)

# Project Go (exclude testdata/ clones).
GOFMT_DIRS := cmd e2e internal scripts/benchclient version.go

all: build

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o socat ./cmd/socat
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o filan ./cmd/filan
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o procan ./cmd/procan

fmt:
	gofmt -w $(GOFMT_DIRS)

fmt-check:
	@out=$$(gofmt -l $(GOFMT_DIRS)); \
	if [ -n "$$out" ]; then \
		echo "gofmt needed:" >&2; \
		echo "$$out" >&2; \
		exit 1; \
	fi

# Enable repo hooks: git config core.hooksPath .githooks
hooks:
	git config core.hooksPath .githooks

lint: fmt-check
	go vet $(GOFLAGS) ./...
	golangci-lint run

# Suppress a finding only at the call site with:
#   // #nosec Gxxx -- reason
# Do not exclude a whole rule.
GOSEC ?= gosec

gosec:
	$(GOSEC) -exclude-dir=testdata \
		-nosec-require-rules -nosec-require-justification \
		./...

test: fmt-check
	go test $(GOFLAGS) ./...

e2e: build
	go test $(GOFLAGS) -tags=e2e ./e2e/...

# Root netns= tests. Host skips without root; Docker uses --privileged.
test-netns-docker:
	./scripts/docker-netns-test.sh

# Optional two-container Compose lab (not part of test or e2e).
lab:
	./examples/lab/run.sh

# Optional loopback benches vs classic C (not part of test or e2e).
bench:
	./scripts/bench.sh

clean:
	rm -f socat filan procan

install: build
	install -d $(BINDIR)
	install -m 755 socat filan procan $(BINDIR)
