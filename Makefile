ifneq (,$(wildcard venv/bin/python))
PYTHON := $(CURDIR)/venv/bin/python
else
PYTHON := python3
endif
GOENV := GOMAXPROCS=4 GOMEMLIMIT=2400MiB

.PHONY: build clean release golden fmt vet test fuzz parity mcp-parity

build:
	mkdir -p build
	$(GOENV) go build -o build/sonic ./cmd/sonic
	$(GOENV) go build -o build/sonic-mcp ./cmd/sonic-mcp

release:
	mkdir -p build/release
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOENV) go build -trimpath -ldflags="-s -w" -o build/release/sonic-linux-amd64 ./cmd/sonic
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOENV) go build -trimpath -ldflags="-s -w" -o build/release/sonic-mcp-linux-amd64 ./cmd/sonic-mcp
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOENV) go build -trimpath -ldflags="-s -w" -o build/release/sonic-linux-arm64 ./cmd/sonic
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOENV) go build -trimpath -ldflags="-s -w" -o build/release/sonic-mcp-linux-arm64 ./cmd/sonic-mcp
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOENV) go build -trimpath -ldflags="-s -w" -o build/release/sonic-darwin-arm64 ./cmd/sonic
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOENV) go build -trimpath -ldflags="-s -w" -o build/release/sonic-mcp-darwin-arm64 ./cmd/sonic-mcp
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOENV) go build -trimpath -ldflags="-s -w" -o build/release/sonic-windows-amd64.exe ./cmd/sonic
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOENV) go build -trimpath -ldflags="-s -w" -o build/release/sonic-mcp-windows-amd64.exe ./cmd/sonic-mcp
	cd build/release && sha256sum sonic-* > SHA256SUMS

clean:
	rm -rf build

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
	$(GOENV) go build -o build/sonic-mcp-stub ./tests/stub_llm_mcp_server.go
	SONIC_CLI_BINARY="$(CURDIR)/build/sonic" SONIC_MCP_BINARY="$(CURDIR)/build/sonic-mcp" SONIC_MCP_STUB_BINARY="$(CURDIR)/build/sonic-mcp-stub" $(PYTHON) -m pytest -q test_mcp_stdio.py test_mcp_guidance.py
	SONIC_MCP_BINARY="$(CURDIR)/build/sonic-mcp" $(PYTHON) -m pytest -q test_network_mcp.py -k TestMcpStdioHandshake
