.PHONY: all build fmt fmt-check lint gosec goos-check test test-scripts e2e e2e-cover coverage check classic-parity fuzz fuzz-matrix test-netns-docker lab bench clean install hooks

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

GOFLAGS ?=
LDFLAGS ?= -s -w -X github.com/oittaa/socat.Version=$(VERSION)

# Project Go (exclude testdata/ clones).
GOFMT_DIRS := cmd e2e internal scripts/benchclient scripts/fuzzall scripts/gooscheck version.go

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
PYTHON ?= python3

gosec:
	$(GOSEC) -exclude-dir=testdata \
		-nosec-require-rules -nosec-require-justification \
		./...

# Reject Go's unix tag, unsupported GOOS names, and !linux/!darwin/!windows/!unix
# in *.go files. Filename suffixes that imply those GOOS values fail too.
# *_unix.go is not an implicit unix tag (Go does not filename-match unix).
goos-check:
	go run $(GOFLAGS) ./scripts/gooscheck

test: fmt-check
	go test $(GOFLAGS) ./...
	$(MAKE) test-scripts

test-scripts:
	$(PYTHON) -B -m unittest discover -s scripts -p '*_test.py'

e2e: build
	go test $(GOFLAGS) -tags=e2e ./e2e/...

# Unit coverage (not part of make check). CI uploads the profile and HTML.
# -coverpkg=./... credits integration tests (for example xio usecases) to the
# packages they execute. go test writes one copy of each block per test
# binary; merge-coverprofile.py combines them the same way go tool cover
# does (OR for set, add for count/atomic) so Codecov heatmaps stay correct.
COVERMODE ?= atomic
COVERAGE_UNIT ?= coverage.unit.out
coverage: fmt-check
	go test $(GOFLAGS) -coverpkg=./... -covermode=$(COVERMODE) -coverprofile=$(COVERAGE_UNIT).raw ./...
	$(PYTHON) -B scripts/merge-coverprofile.py $(COVERAGE_UNIT).raw $(COVERAGE_UNIT)
	rm -f $(COVERAGE_UNIT).raw
	./scripts/coverage-summary.sh $(COVERAGE_UNIT)

# E2E coverage of the socat binary (go build -cover + GOCOVERDIR). This is how
# to tell whether an e2e test actually reached the code it names: functions
# that stay at 0.0% were never executed by the instrumented binary.
COVERDIR ?= coverage/e2e
COVERAGE_E2E ?= coverage.e2e.out
e2e-cover:
	rm -rf $(COVERDIR)
	mkdir -p $(COVERDIR)
	go build $(GOFLAGS) -cover -covermode=$(COVERMODE) -ldflags '$(LDFLAGS)' -o socat ./cmd/socat
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o filan ./cmd/filan
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o procan ./cmd/procan
	GOCOVERDIR="$(CURDIR)/$(COVERDIR)" go test $(GOFLAGS) -tags=e2e ./e2e/...
	go tool covdata percent -i="$(COVERDIR)"
	go tool covdata textfmt -i="$(COVERDIR)" -o $(COVERAGE_E2E)
	./scripts/coverage-summary.sh $(COVERAGE_E2E)

# Complete pre-commit validation. Keep these recursive calls sequential so a
# failure identifies the stage clearly even when the caller enables make -j.
check:
	$(MAKE) lint
	$(MAKE) gosec
	$(MAKE) goos-check
	$(MAKE) test
	$(MAKE) e2e

# Native Go vs official release and reviewed master. Needs repo.or.cz.
# Not part of check: ordinary development stays offline from that host.
# Working trees, binaries, and -hhh/-V dumps stay under testdata/tmp/.
classic-parity:
	$(PYTHON) -B scripts/classic-parity.py run

# Native Go fuzz campaigns. Weekly/manual in deep-tests.yml, not per-commit CI.
# Windows: go run ./scripts/fuzzall -fuzztime=30s
FUZZTIME ?= 30s
fuzz:
	go run ./scripts/fuzzall -fuzztime=$(FUZZTIME)

# Bounded live relay matrix (byte-pipe families x directions). Weekly/manual in
# deep-tests.yml, not per-commit CI.
fuzz-matrix: build
	go test $(GOFLAGS) -tags=e2e,relaymatrix -run '^TestRelayMatrix' ./e2e/ -count=1 -timeout=10m

# Root netns= and IP4-RECVFROM tests. Host skips without root; Docker uses --privileged.
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
