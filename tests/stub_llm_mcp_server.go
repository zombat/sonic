//go:build ignore

// Test launcher: the real S.O.N.I.C. Go MCP server with a stubbed streaming LLM.
// Only llm.Completer is replaced by a stub emitting STUB_REPORT without network or key;
// flag parsing, credential loading, stdout reservation, stdio transport, SIP extraction,
// quality/MOS scoring, and redaction all run through the production path.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/zombat/sonic/internal/ai"
	"github.com/zombat/sonic/internal/llm"
	"github.com/zombat/sonic/internal/mcpserver"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/report"
)

const stubReportJSON = `{"calls":[],"overallAssessment":"stub diagnosis","stub":true}`

type stubCompleter struct{}

func (stubCompleter) Complete(
	_ context.Context,
	provider, _, modelName string,
	_ []llm.Message,
	_ json.RawMessage,
	onToken func(string),
) (llm.Response, llm.Usage, error) {
	parts := strings.Split(stubReportJSON, " ")
	for _, part := range parts {
		if onToken != nil {
			onToken(part + " ")
		}
	}
	return llm.Response{
		Text:         stubReportJSON,
		OutputTokens: len(parts),
		Reported:     true,
		Model:        modelName,
	}, llm.Usage{
		Provider:     provider,
		Model:        modelName,
		OutputTokens: len(parts),
	}, nil
}

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("stub-sonic-mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var envFile string
	fs.StringVar(&envFile, "env-file", "", "dotenv file to read API keys from when unset ($SONIC_ENV_FILE)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	creds, err := llm.NewCredentialStore(envFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load env file: %s\n", redact.RedactText(err.Error()))
		var envErr *llm.EnvFileError
		if errors.As(err, &envErr) {
			return 2
		}
		return 1
	}
	srv, err := mcpserver.NewWithDeps(ai.Deps{Creds: creds, Completer: stubCompleter{}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize stub mcp server: %s\n", redact.RedactText(err.Error()))
		return 1
	}
	reserved, restore, err := report.ReserveStdoutForProtocol()
	if err != nil {
		fmt.Fprintf(os.Stderr, "reserve protocol stdout: %s\n", redact.RedactText(err.Error()))
		return 1
	}
	defer restore()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := srv.Serve(ctx, os.Stdin, reserved); err != nil {
		fmt.Fprintf(os.Stderr, "serve stub mcp stdio: %s\n", redact.RedactText(err.Error()))
		return 1
	}
	return 0
}
