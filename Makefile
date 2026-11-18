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

.DEFAULT_GOAL := build

.PHONY: all build install uninstall release docker clean fmt vet test fuzz parity update-golden help

all: build

build:
	@mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 $(GOENV) go build $(GO_FLAGS) -o "$(BUILD_DIR)/sonic" ./cmd/sonic
	CGO_ENABLED=0 $(GOENV) go build $(GO_FLAGS) -o "$(BUILD_DIR)/sonic-mcp" ./cmd/sonic-mcp

docker:
	docker build --build-arg VERSION="$(VERSION)" --build-arg COMMIT="$(COMMIT)" -t "sonic:$(VERSION)" .

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
	$(GOENV) go test -run=^$$ -fuzz=FuzzExtractBalancedJSON -fuzztime=1s ./internal/ai
	$(GOENV) go test -run=^$$ -fuzz=FuzzArtifactFactoryBuild -fuzztime=1s ./internal/ai

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
	@printf "  fuzz           Run 1s fuzz smoke tests on SSE, NDJSON, JSON recovery, and ArtifactFactory\n"
	@printf "  parity         Run Go golden JSON parity tests against testdata/golden/\n"
	@printf "  update-golden  Regenerate golden JSON snapshots via go test -update\n"
	@printf "  docker         Build minimal rootless container image bundling sonic, sonic-mcp, and headless tshark\n"
	@printf "  clean          Remove build/ artifacts\n"
