.PHONY: all build fmt fmt-check lint gosec test e2e lab bench clean install hooks

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

# G103 unsafe: PTY ioctl and POSIX MQ syscalls.
# G104 unhandled Close: cleanup after a prior error.
# G115 int conversion: poll fd, SOCKS length (checked), ancillary ABI.
# G204/G702 EXEC/SYSTEM/SHELL: user-supplied command is the feature.
# G302/G306 0644/0664: logs, lock file, sniff, /proc sysctl.
# G304/G703 path from option: OPEN/FILE/cert=/filan is the feature.
GOSEC_EXCLUDE ?= G103,G104,G115,G204,G302,G304,G306,G702,G703
GOSEC ?= gosec

gosec:
	$(GOSEC) -exclude-dir=testdata -exclude=$(GOSEC_EXCLUDE) ./...

test: fmt-check
	go test $(GOFLAGS) ./...

e2e: build
	go test $(GOFLAGS) -tags=e2e ./e2e/...

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
