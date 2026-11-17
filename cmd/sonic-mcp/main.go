// Package main provides the thin S.O.N.I.C. MCP stdio server composition root,
// reserving standard output strictly for JSON-RPC 2.0 protocol frames.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/zombat/sonic/internal/mcpserver"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/report"
)

type runtimeDeps struct {
	newServer     func() (*mcpserver.Server, error)
	reserveStdout func() (*os.File, func(), error)
}

func defaultDeps() runtimeDeps {
	return runtimeDeps{
		newServer:     mcpserver.NewDefault,
		reserveStdout: report.ReserveStdoutForProtocol,
	}
}

func main() {
	os.Exit(run(context.Background(), os.Stdin, os.Stdout, os.Stderr, true, defaultDeps()))
}

func run(ctx context.Context, in io.Reader, out io.Writer, errOut io.Writer, reserveFD bool, deps runtimeDeps) int {
	srv, err := deps.newServer()
	if err != nil {
		fmt.Fprintf(errOut, "initialize mcp server: %s\n", redact.RedactText(err.Error()))
		return 1
	}

	protoOut := out
	if reserveFD {
		reserved, restore, rerr := deps.reserveStdout()
		if rerr != nil {
			fmt.Fprintf(errOut, "reserve protocol stdout: %s\n", redact.RedactText(rerr.Error()))
			return 1
		}
		defer restore()
		protoOut = reserved
	}

	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := srv.Serve(sigCtx, in, protoOut); err != nil {
		fmt.Fprintf(errOut, "serve mcp stdio: %s\n", redact.RedactText(err.Error()))
		return 1
	}
	return 0
}
