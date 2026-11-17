// Package main defines Phase 7 LLM CLI option types, flag registration,
// option validation, and credential store loading.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/zombat/sonic/internal/ai"
	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/guide"
	"github.com/zombat/sonic/internal/llm"
	"github.com/zombat/sonic/internal/redact"
)

type llmCLIOptions struct {
	model        string
	provider     string
	modelName    string
	quality      bool
	mos          bool
	stream       bool
	partial      bool
	batchDir     string
	batchMode    string
	batchWorkers int
	verbose      bool
}

type llmRuntimeDeps struct {
	fetchProtos func(ctx context.Context, dest string) grpc.FetchResult
	completer   llm.Completer
	factory     *ai.ArtifactFactory
}

func defaultLLMRuntimeDeps() llmRuntimeDeps {
	return llmRuntimeDeps{
		fetchProtos: func(ctx context.Context, dest string) grpc.FetchResult {
			return grpc.FetchProtos(ctx, dest, nil, nil)
		},
	}
}

func extractFetchProtosFlag(args []string) (string, bool, []string) {
	return guide.ExtractOptionalFlag(args, "--fetch-grpc-protos", grpc.DefaultProtoDir())
}

func registerLLMFlags(fs *flag.FlagSet, lo *llmCLIOptions) {
	fs.StringVar(&lo.model, "model", "combined", "SIP LLM mode: fast, detailed, deep, combined, or all")
	fs.StringVar(&lo.provider, "provider", "", "LLM provider: ollama, anthropic, openai, or azure")
	fs.StringVar(&lo.modelName, "model-name", "", "override concrete LLM model name")
	fs.BoolVar(&lo.quality, "quality", false, "include deterministic call quality scoring in SIP LLM mode")
	fs.BoolVar(&lo.mos, "mos", false, "include RTP MOS estimation in SIP LLM mode")
	fs.BoolVar(&lo.stream, "stream", false, "stream combined SIP LLM diagnosis output")
	fs.BoolVar(&lo.partial, "partial", false, "emit deterministic quality and MOS before streaming LLM diagnosis")
	fs.StringVar(&lo.batchDir, "batch-dir", "", "analyze every *.pcap* file in DIR in batch mode")
	fs.StringVar(&lo.batchMode, "batch-mode", string(ai.ModeSequential), "batch execution mode: sequential or parallel")
	fs.IntVar(&lo.batchWorkers, "batch-workers", 3, "concurrent workers when --batch-mode parallel is selected")
	fs.BoolVar(&lo.verbose, "verbose", false, "emit detailed progress to stderr")
}

func hasVisitedFlag(fs *flag.FlagSet, name string) bool {
	visited := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			visited = true
		}
	})
	return visited
}

func isDeterministicMode(o cliOptions, fs *flag.FlagSet) bool {
	return o.grpcMode || o.restconfMode || o.snmpMode || o.aaaMode ||
		o.espDecrypt || o.qualityOnly || o.networkOnly ||
		hasVisitedFlag(fs, "detectors") || o.allowCSV != ""
}

func validateLLMOptions(lo llmCLIOptions, stderr io.Writer) bool {
	switch lo.model {
	case "fast", "detailed", "deep", "combined", "all":
	default:
		fmt.Fprintf(stderr, "invalid --model %q: expected fast, detailed, deep, combined, or all\n", lo.model)
		return false
	}
	if lo.provider != "" {
		if _, ok := llm.Lookup(lo.provider); !ok {
			fmt.Fprintf(stderr, "invalid --provider %q: expected ollama, anthropic, openai, or azure\n", lo.provider)
			return false
		}
	}
	if lo.modelName != "" && lo.model == "all" {
		fmt.Fprintln(stderr, "--model-name cannot be used with --model all, which tests its own models")
		return false
	}
	switch lo.batchMode {
	case string(ai.ModeSequential), string(ai.ModeParallel):
	default:
		fmt.Fprintf(stderr, "invalid --batch-mode %q: expected sequential or parallel\n", lo.batchMode)
		return false
	}
	if lo.batchWorkers < 1 {
		fmt.Fprintf(stderr, "invalid --batch-workers %d: must be at least 1\n", lo.batchWorkers)
		return false
	}
	return true
}

func loadCredentialsForCLI(envFile string, stderr io.Writer) (*llm.CredentialStore, int) {
	creds, err := llm.NewCredentialStore(envFile)
	if err == nil {
		return creds, 0
	}
	fmt.Fprintf(stderr, "load env file: %s\n", redact.RedactText(err.Error()))
	var envErr *llm.EnvFileError
	if errors.As(err, &envErr) {
		return nil, 2
	}
	return nil, 1
}

func buildAIDeps(creds *llm.CredentialStore, deps llmRuntimeDeps) ai.Deps {
	return ai.Deps{Creds: creds, Completer: deps.completer, Factory: deps.factory}
}
