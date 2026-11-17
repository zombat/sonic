// Package main provides the thin S.O.N.I.C. MCP stdio server composition root,
// reserving standard output strictly for JSON-RPC 2.0 protocol frames.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/zombat/sonic/internal/ai"
	"github.com/zombat/sonic/internal/guide"
	"github.com/zombat/sonic/internal/llm"
	"github.com/zombat/sonic/internal/mcpserver"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/report"
)

type runtimeDeps struct {
	loadCreds     func(envFile string) (*llm.CredentialStore, error)
	newServer     func(deps ai.Deps) (*mcpserver.Server, error)
	reserveStdout func() (*os.File, func(), error)
}

func defaultDeps() runtimeDeps {
	return runtimeDeps{
		loadCreds:     llm.NewCredentialStore,
		newServer:     mcpserver.NewWithDeps,
		reserveStdout: report.ReserveStdoutForProtocol,
	}
}

func main() {
	os.Exit(runWithArgs(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, true, defaultDeps()))
}

func runWithArgs(ctx context.Context, args []string, in io.Reader, out io.Writer, errOut io.Writer, reserveFD bool, deps runtimeDeps) int {
	skillDir, createSkill, cleanArgs := guide.ExtractCreateSkillFlag(args)
	fs := flag.NewFlagSet("sonic-mcp", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var envFile string
	fs.StringVar(&envFile, "env-file", "", "dotenv file to read API keys from when unset ($SONIC_ENV_FILE)")
	if err := fs.Parse(cleanArgs); err != nil {
		return 2
	}

	creds, cerr := deps.loadCreds(envFile)
	if cerr != nil {
		fmt.Fprintf(errOut, "load env file: %s\n", redact.RedactText(cerr.Error()))
		var envErr *llm.EnvFileError
		if errors.As(cerr, &envErr) {
			return 2
		}
		return 1
	}

	srv, err := deps.newServer(ai.Deps{Creds: creds})
	if err != nil {
		fmt.Fprintf(errOut, "initialize mcp server: %s\n", redact.RedactText(err.Error()))
		return 1
	}
	if createSkill {
		return guide.CreateSkillCommand(skillDir, srv.ToolSpecs(), "sonic", guide.DefaultCLIFlags(), out, errOut)
	}
	return serveServer(ctx, srv, in, out, errOut, reserveFD, deps)
}

func serveServer(ctx context.Context, srv *mcpserver.Server, in io.Reader, out io.Writer, errOut io.Writer, reserveFD bool, deps runtimeDeps) int {
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
