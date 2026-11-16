PYTHON := /home/noot/sonic/venv/bin/python
GOENV := GOMAXPROCS=4 GOMEMLIMIT=2400MiB

.PHONY: golden fmt vet test parity

golden:
	$(PYTHON) tools/gen_golden.py

fmt:
	gofmt -w .

vet:
	$(GOENV) go vet ./...

test:
	$(GOENV) go test -race -p 1 -count=1 -cover ./...

parity:
	$(GOENV) go test -race -p 1 -count=1 -run 'Golden' ./internal/extract/... ./internal/analyze/audit/... ./cmd/sonic/...
