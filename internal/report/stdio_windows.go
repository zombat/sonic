//go:build windows

// Package report reserves standard output exclusively for the MCP JSON-RPC wire
// channel while redirecting Go-level os.Stdout writes to stderr on Windows.
package report

import (
	"os"
	"sync"
)

// ReserveStdoutForProtocol captures the original stdout handle for MCP JSON-RPC frames,
// points os.Stdout at os.Stderr, and returns an idempotent restore callback.
func ReserveStdoutForProtocol() (protoOut *os.File, restore func(), err error) {
	origStdout := os.Stdout
	os.Stdout = os.Stderr
	var once sync.Once
	restoreFn := func() {
		once.Do(func() {
			os.Stdout = origStdout
		})
	}
	return origStdout, restoreFn, nil
}
