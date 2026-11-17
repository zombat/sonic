# S.O.N.I.C. Makefile
#
# Compile & install Go binaries (tshark required on PATH at runtime):
#   make               Compile ./build/sonic and ./build/sonic-mcp
#   make install       Install binaries into $(PREFIX) (default ~/.local/bin)
#   make release       Cross-compile stripped CGO_ENABLED=0 binaries + SHA256SUMS
#   make test          Run all 34 Go packages with -race and statement coverage
#   make help          List all targets and configurable variables

ifneq (,$(wildcard venv/bin/python))
PYTHON := $(CURDIR)/venv/bin/python
else
PYTHON := python3
endif

GOENV     ?= GOMAXPROCS=4 GOMEMLIMIT=2400MiB
BUILD_DIR ?= build
REL_DIR   ?= $(BUILD_DIR)/release
PREFIX    ?= $(HOME)/.local/bin
LDFLAGS   ?= -s -w
GO_FLAGS  ?= -trimpath -ldflags="$(LDFLAGS)"

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

.DEFAULT_GOAL := build
.PHONY: all build install uninstall clean release golden fmt vet test fuzz parity mcp-parity help

all: build

build:
	@mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 $(GOENV) go build $(GO_FLAGS) -o "$(BUILD_DIR)/sonic" ./cmd/sonic
	CGO_ENABLED=0 $(GOENV) go build $(GO_FLAGS) -o "$(BUILD_DIR)/sonic-mcp" ./cmd/sonic-mcp

install: build
	@mkdir -p "$(PREFIX)"
	install -m 0755 "$(BUILD_DIR)/sonic" "$(PREFIX)/sonic"
	install -m 0755 "$(BUILD_DIR)/sonic-mcp" "$(PREFIX)/sonic-mcp"

uninstall:
	rm -f "$(PREFIX)/sonic" "$(PREFIX)/sonic-mcp"

release:
	@mkdir -p "$(REL_DIR)"
	@set -e; for pair in $(PLATFORMS); do \
		os="$${pair%/*}"; \
		arch="$${pair#*/}"; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building $$os/$$arch..."; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GOENV) go build $(GO_FLAGS) -o "$(REL_DIR)/sonic-$$os-$$arch$$ext" ./cmd/sonic; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GOENV) go build $(GO_FLAGS) -o "$(REL_DIR)/sonic-mcp-$$os-$$arch$$ext" ./cmd/sonic-mcp; \
	done
	@cd "$(REL_DIR)" && sha256sum sonic-* > SHA256SUMS

clean:
	rm -rf "$(BUILD_DIR)"

golden:
	$(PYTHON) tools/gen_golden.py

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
	$(GOENV) go test -race -p 1 -count=1 -run 'Golden' ./internal/extract/... ./internal/analyze/audit/... ./cmd/sonic/... ./internal/mcpserver/...

mcp-parity: build
	$(GOENV) go build -o "$(BUILD_DIR)/sonic-mcp-stub" ./tests/stub_llm_mcp_server.go
	SONIC_CLI_BINARY="$(CURDIR)/$(BUILD_DIR)/sonic" SONIC_MCP_BINARY="$(CURDIR)/$(BUILD_DIR)/sonic-mcp" SONIC_MCP_STUB_BINARY="$(CURDIR)/$(BUILD_DIR)/sonic-mcp-stub" $(PYTHON) -m pytest -q test_mcp_stdio.py test_mcp_guidance.py
	SONIC_MCP_BINARY="$(CURDIR)/$(BUILD_DIR)/sonic-mcp" $(PYTHON) -m pytest -q test_network_mcp.py -k TestMcpStdioHandshake

help:
	@echo "S.O.N.I.C. Makefile targets:"
	@echo "  build       Compile $(BUILD_DIR)/sonic and $(BUILD_DIR)/sonic-mcp (default)"
	@echo "  install     Install sonic and sonic-mcp into PREFIX (default: $(PREFIX))"
	@echo "  uninstall   Remove sonic and sonic-mcp from PREFIX"
	@echo "  release     Cross-compile stripped static binaries ($(PLATFORMS)) + SHA256SUMS"
	@echo "  vet         Run go vet ./..."
	@echo "  fmt         Format all Go files with gofmt -w ."
	@echo "  test        Run all 34 Go packages with -race and coverage"
	@echo "  fuzz        Run 1s fuzz smoke tests on SSE, NDJSON, JSON recovery, and ArtifactFactory"
	@echo "  parity      Run Go golden JSON parity tests"
	@echo "  mcp-parity  Run Python MCP stdio/guidance suites against compiled Go binaries"
	@echo "  golden      Regenerate Python golden JSON fixtures"
	@echo "  clean       Remove $(BUILD_DIR)/ artifacts"
