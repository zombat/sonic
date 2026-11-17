// Package ai implements bounded sequential and parallel batch SIP capture analysis.
package ai

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/zombat/sonic/internal/llm"
)

// CollectBatchPcaps returns sorted non-directory *.pcap* capture paths directly under dir.
func CollectBatchPcaps(dir string) ([]string, error) {
	if dir == "" {
		return nil, fmt.Errorf("directory not found: %s", dir)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("directory not found: %s", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("directory not readable: %s", dir)
	}
	var out []string
	for _, entry := range entries {
		matched, merr := filepath.Match("*.pcap*", entry.Name())
		if merr != nil || !matched {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		st, serr := os.Stat(full)
		if serr != nil || st.IsDir() {
			continue
		}
		out = append(out, full)
	}
	slices.Sort(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no pcap files found in directory: %s", dir)
	}
	return out, nil
}

// AnalyzeBatch runs streaming SIP LLM diagnosis across filePaths sequentially or with bounded concurrency.
func AnalyzeBatch(
	ctx context.Context,
	deps Deps,
	filePaths []string,
	provider, model string,
	mode ProcessingMode,
	maxWorkers int,
	modelName string,
	onProgress func(BatchProgress),
	onToken func(string),
) BatchResult {
	if mode != ModeParallel {
		mode = ModeSequential
	}
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	resolved := llm.ResolveProvider(provider)
	res := BatchResult{
		Status: "success",
		BatchMetadata: BatchMetadata{
			Mode:       mode,
			TotalFiles: len(filePaths),
			Provider:   resolved,
			Model:      model,
		},
		Files: make([]BatchFileResult, len(filePaths)),
		Aggregate: BatchAggregate{
			QualitySummary: BatchQualitySummary{
				CallsByGrade: make(map[string]int),
			},
		},
	}
	start := time.Now()
	workers := 1
	if mode == ModeParallel {
		workers = min(maxWorkers, max(1, len(filePaths)))
	}
	sem := make(chan struct{}, workers)
	var cbMu sync.Mutex
	var safeProgress func(BatchProgress)
	if onProgress != nil {
		safeProgress = func(p BatchProgress) {
			cbMu.Lock()
			defer cbMu.Unlock()
			onProgress(p)
		}
	}
	var safeToken func(string)
	if onToken != nil {
		safeToken = func(tok string) {
			cbMu.Lock()
			defer cbMu.Unlock()
			onToken(tok)
		}
	}
	var wg sync.WaitGroup
	for idx, fp := range filePaths {
		wg.Add(1)
		go func(i int, path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res.Files[i] = analyzeBatchOne(ctx, deps, path, i, len(filePaths), resolved, modelName, safeProgress, safeToken)
		}(idx, fp)
	}
	wg.Wait()

	for _, fr := range res.Files {
		if fr.Status == "success" {
			res.Aggregate.Successful++
			if fr.StreamingMetadata != nil {
				res.Aggregate.TotalTokens += fr.StreamingMetadata.TotalTokens
			}
		} else {
			res.Aggregate.Failed++
		}
	}
	res.Aggregate.TotalDuration = time.Since(start).Seconds()
	return res
}

func analyzeBatchOne(
	ctx context.Context,
	deps Deps,
	filePath string,
	idx, totalFiles int,
	provider, modelName string,
	onProgress func(BatchProgress),
	onToken func(string),
) BatchFileResult {
	if onProgress != nil {
		onProgress(BatchProgress{FilePath: filePath, Index: idx, TotalFiles: totalFiles, Status: "analyzing"})
	}
	start := time.Now()
	var tokens int
	cb := func(tok string) {
		tokens++
		if onToken != nil {
			onToken(tok)
		}
	}
	sipText, _, err := extractSIPText(ctx, filePath)
	if err != nil {
		elapsed := time.Since(start).Seconds()
		if onProgress != nil {
			onProgress(BatchProgress{FilePath: filePath, Index: idx, TotalFiles: totalFiles, Status: "error", ElapsedTime: elapsed, Error: "No SIP data found"})
		}
		return BatchFileResult{Status: "error", File: filePath, Index: idx, Error: "No SIP data found", ElapsedTime: elapsed}
	}
	outRes, _ := RunCombinedAnalysisStreaming(ctx, deps, sipText, filePath, provider, modelName, cb, nil)
	elapsed := time.Since(start).Seconds()
	if outRes.Status != "success" {
		if onProgress != nil {
			onProgress(BatchProgress{FilePath: filePath, Index: idx, TotalFiles: totalFiles, Status: "error", ElapsedTime: elapsed, TokensStreamed: tokens, Error: outRes.Error})
		}
		return BatchFileResult{Status: "error", File: filePath, Index: idx, Error: outRes.Error, ElapsedTime: elapsed}
	}
	if tokens == 0 && outRes.StreamingMetadata != nil {
		tokens = outRes.StreamingMetadata.TotalTokens
	}
	if onProgress != nil {
		onProgress(BatchProgress{FilePath: filePath, Index: idx, TotalFiles: totalFiles, Status: "completed", ElapsedTime: elapsed, TokensStreamed: tokens})
	}
	return BatchFileResult{
		Status:            "success",
		File:              filePath,
		Index:             idx,
		Output:            outRes.Output,
		ElapsedTime:       elapsed,
		StreamingMetadata: &StreamingMeta{TotalTokens: tokens, Provider: provider, ElapsedTime: elapsed},
	}
}
