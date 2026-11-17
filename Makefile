ifneq (,$(wildcard venv/bin/python))
PYTHON := $(CURDIR)/venv/bin/python
else
PYTHON := python3
endif
GOENV := GOMAXPROCS=4 GOMEMLIMIT=2400MiB

.PHONY: build clean golden fmt vet test fuzz parity mcp-parity

build:
	mkdir -p build
	$(GOENV) go build -o build/sonic ./cmd/sonic
	$(GOENV) go build -o build/sonic-mcp ./cmd/sonic-mcp

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
