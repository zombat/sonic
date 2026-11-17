// Package report reserves standard output exclusively for the MCP JSON-RPC wire
// channel while redirecting any stray fd 1 / os.Stdout writes to stderr.
package report

import (
	"fmt"
	"os"
	"sync"
	"syscall"
)

// ReserveStdoutForProtocol duplicates file descriptor 1 onto a dedicated *os.File for
// protocol output, points fd 1 and os.Stdout at stderr, and returns an idempotent restore
// function. This mirrors utils/protocol_stdout.py so stray stdout writes never corrupt MCP stdio.
func ReserveStdoutForProtocol() (protoOut *os.File, restore func(), err error) {
	protoFD, err := syscall.Dup(1)
	if err != nil {
		return nil, nil, fmt.Errorf("dup stdout fd: %w", err)
	}
	origStdout := os.Stdout
	if err := syscall.Dup2(2, 1); err != nil {
		_ = syscall.Close(protoFD)
		return nil, nil, fmt.Errorf("redirect fd 1 to stderr: %w", err)
	}
	os.Stdout = os.Stderr
	protoFile := os.NewFile(uintptr(protoFD), "mcp-protocol-stdout")
	if protoFile == nil {
		_ = syscall.Dup2(protoFD, 1)
		_ = syscall.Close(protoFD)
		os.Stdout = origStdout
		return nil, nil, fmt.Errorf("wrap protocol stdout fd")
	}
	var once sync.Once
	restoreFn := func() {
		once.Do(func() {
			os.Stdout = origStdout
			_ = syscall.Dup2(protoFD, 1)
			_ = protoFile.Close()
		})
	}
	return protoFile, restoreFn, nil
}
