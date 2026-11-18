# Build, install, release, test, and verify S.O.N.I.C. (pure Go runtime).
# Common usage:
#   make               Compile build/sonic and build/sonic-mcp
#   make install       Install sonic and sonic-mcp into PREFIX (~/.local/bin)
#   make release       Build release archives (.tar.gz / .zip) + SHA256SUMS for 6 platforms
#   make test          Run all Go packages with -race and coverage
#   make update-golden Update golden JSON snapshots via go test -update
#   make help          Print all available targets

GOENV ?= GOMAXPROCS=4 GOMEMLIMIT=2400MiB
BUILD_DIR ?= build
REL_DIR ?= $(BUILD_DIR)/release
PREFIX ?= $(HOME)/.local/bin
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS ?= -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
GO_FLAGS ?= -trimpath -ldflags="$(LDFLAGS)"
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
CONTAINER_ENGINE ?= $(shell if command -v docker >/dev/null 2>&1; then echo docker; elif command -v podman >/dev/null 2>&1; then echo podman; fi)
CONTAINER_IMAGE ?= sonic:$(VERSION)
CONTAINER_NAME ?= sonic
CAPTURES_DIR ?= $(CURDIR)/testdata/fixtures

.DEFAULT_GOAL := build

.PHONY: all build install uninstall release container container-up container-down clean fmt vet test fuzz parity update-golden help

all: build

build:
	@mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 $(GOENV) go build $(GO_FLAGS) -o "$(BUILD_DIR)/sonic" ./cmd/sonic
	CGO_ENABLED=0 $(GOENV) go build $(GO_FLAGS) -o "$(BUILD_DIR)/sonic-mcp" ./cmd/sonic-mcp

container:
	@if [ -z "$(CONTAINER_ENGINE)" ]; then echo "error: neither docker nor podman found on PATH" >&2; exit 1; fi
	$(CONTAINER_ENGINE) build --build-arg VERSION="$(VERSION)" --build-arg COMMIT="$(COMMIT)" -t "$(CONTAINER_IMAGE)" .

container-up: container
	@$(CONTAINER_ENGINE) rm -f "$(CONTAINER_NAME)" >/dev/null 2>&1 || true
	$(CONTAINER_ENGINE) run -d --name "$(CONTAINER_NAME)" --entrypoint /bin/sh -v "$(CAPTURES_DIR):/captures:ro" "$(CONTAINER_IMAGE)" -c "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $$!; done"
	@printf "\nS.O.N.I.C. container running (no web UI; CLI + MCP stdio only):\n"
	@printf "  Engine:    %s\n" "$(CONTAINER_ENGINE)"
	@printf "  Container: %s (%s)\n" "$(CONTAINER_NAME)" "$(CONTAINER_IMAGE)"
	@printf "  Captures:  %s -> /captures (ro)\n" "$(CAPTURES_DIR)"
	@printf "  CLI:       %s exec %s sonic --file /captures/<file.pcap> --network-only\n" "$(CONTAINER_ENGINE)" "$(CONTAINER_NAME)"
	@printf "  MCP stdio: %s exec -i %s sonic-mcp\n" "$(CONTAINER_ENGINE)" "$(CONTAINER_NAME)"
	@printf "  Shell:     %s exec -it %s /bin/sh\n" "$(CONTAINER_ENGINE)" "$(CONTAINER_NAME)"
	@printf "  Stop:      make container-down\n"

container-down:
	@if [ -z "$(CONTAINER_ENGINE)" ]; then echo "error: neither docker nor podman found on PATH" >&2; exit 1; fi
	-$(CONTAINER_ENGINE) rm -f "$(CONTAINER_NAME)"

install: build
	install -d "$(PREFIX)"
	install -m 0755 "$(BUILD_DIR)/sonic" "$(PREFIX)/sonic"
	install -m 0755 "$(BUILD_DIR)/sonic-mcp" "$(PREFIX)/sonic-mcp"

uninstall:
	rm -f "$(PREFIX)/sonic" "$(PREFIX)/sonic-mcp"

release:
	@rm -rf "$(REL_DIR)" && mkdir -p "$(REL_DIR)/stage"
	@for p in $(PLATFORMS); do \
		os="$${p%/*}"; arch="$${p#*/}"; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		bundle="$(REL_DIR)/stage/sonic-$(VERSION)-$$os-$$arch"; \
		mkdir -p "$$bundle"; \
		echo "Building $$os/$$arch ($(VERSION))..."; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GOENV) go build $(GO_FLAGS) -o "$$bundle/sonic$$ext" ./cmd/sonic || exit 1; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GOENV) go build $(GO_FLAGS) -o "$$bundle/sonic-mcp$$ext" ./cmd/sonic-mcp || exit 1; \
		cp LICENSE README.md "$$bundle/" || exit 1; \
	done
	$(GOENV) go run tools/pack_release.go -stage "$(REL_DIR)/stage" -out "$(REL_DIR)"
	@rm -rf "$(REL_DIR)/stage"
	@cat "$(REL_DIR)/SHA256SUMS"

clean:
	rm -rf "$(BUILD_DIR)"

fmt:
	gofmt -w .

vet:
	$(GOENV) go vet ./...

test:
	$(GOENV) go test -race -p 1 -count=1 -cover ./...

fuzz:
	$(GOENV) go test -run=^$$ -fuzz=FuzzSSEEvents -fuzztime=1s ./internal/llm
	$(GOENV) go test -run=^$$ -fuzz=FuzzNDJSON -fuzztime=1s ./internal/llm
	$(GOENV) go test -run=^$$ -fuzz=FuzzValidateBaseURL -fuzztime=1s ./internal/llm
	$(GOENV) go test -run=^$$ -fuzz=FuzzExtractBalancedJSON -fuzztime=1s ./internal/ai
	$(GOENV) go test -run=^$$ -fuzz=FuzzArtifactFactoryBuild -fuzztime=1s ./internal/ai
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseAllowlist -fuzztime=1s ./internal/analyze/audit
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseKexInit -fuzztime=1s ./internal/analyze/audit
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseClientHello -fuzztime=1s ./internal/analyze/tlsinspect
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseServerHello -fuzztime=1s ./internal/analyze/tlsinspect
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseCertificate -fuzztime=1s ./internal/analyze/tlsinspect
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseIKE -fuzztime=1s ./internal/extract
	$(GOENV) go test -run=^$$ -fuzz=FuzzFastPathPCAP -fuzztime=1s ./internal/extract
	$(GOENV) go test -run=^$$ -fuzz=FuzzDecodeFastPacket -fuzztime=1s ./internal/extract
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseSIPAndSDP -fuzztime=1s ./internal/extract
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseDotenv -fuzztime=1s ./internal/redact
	$(GOENV) go test -run=^$$ -fuzz=FuzzMaskSecretShapes -fuzztime=1s ./internal/redact
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseEKLine -fuzztime=1s ./internal/tshark
	$(GOENV) go test -run=^$$ -fuzz=FuzzParsePolicies -fuzztime=1s ./internal/gate
	$(GOENV) go test -run=^$$ -fuzz=FuzzParseReportDigest -fuzztime=1s ./internal/report
	$(GOENV) go test -run=^$$ -fuzz=FuzzSanitizeTerminalText -fuzztime=1s ./internal/tui

parity:
	$(GOENV) go test -race -p 1 -count=1 -run 'Golden' ./...

update-golden:
	$(GOENV) go test -p 1 -count=1 ./... -update

help:
	@printf "S.O.N.I.C. Makefile targets:\n"
	@printf "  build          Compile build/sonic and build/sonic-mcp (default)\n"
	@printf "  install        Install sonic and sonic-mcp into PREFIX (default: $(HOME)/.local/bin)\n"
	@printf "  uninstall      Remove sonic and sonic-mcp from PREFIX\n"
	@printf "  release        Cross-compile archives (.tar.gz / .zip) + SHA256SUMS for 6 OS/arch targets\n"
	@printf "  vet            Run go vet ./...\n"
	@printf "  fmt            Format all Go files with gofmt -w .\n"
	@printf "  test           Run all Go packages with -race and coverage\n"
	@printf "  fuzz           Run 1s fuzz smoke tests across all 20 fuzz targets\n"
	@printf "  parity         Run Go golden JSON parity tests against testdata/golden/\n"
	@printf "  update-golden  Regenerate golden JSON snapshots via go test -update\n"
	@printf "  container      Build minimal rootless container image using docker or podman\n"
	@printf "  container-up   Start background container with CAPTURES_DIR mounted at /captures\n"
	@printf "  container-down Stop and remove the running container\n"
	@printf "  clean          Remove build/ artifacts\n"
