// Package espdecrypt orchestrates SA file loading, ESP decryption, inner packet
// reconstruction, and nested network-detector reporting without exposing keys.
package espdecrypt

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

// errReport constructs a minimal error Report payload.
func errReport(msg string) Report {
	return Report{Status: "error", Error: msg}
}

// AnalyzeCapture decrypts ESP packets using opts.SAFile and analyzes reconstructed inner traffic.
func AnalyzeCapture(ctx context.Context, filePath string, opts Options) Report {
	if filePath == "" {
		return errReport("File not found: " + filePath)
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return errReport("File not found: " + filePath)
	}
	if info.IsDir() {
		return errReport("File not readable: " + filePath)
	}
	if f, openErr := os.Open(filePath); openErr != nil {
		return errReport("File not readable: " + filePath)
	} else {
		_ = f.Close()
	}
	if !tshark.Available("") {
		return errReport("ESP decryption needs tshark (Wireshark's ESP decryption); install it")
	}
	if opts.SAFile == "" {
		return errReport("ESP decryption needs an SA file (sa_file): S.O.N.I.C.'s SA format or `ip xfrm state` output")
	}
	saInfo, saErr := os.Stat(opts.SAFile)
	if saErr != nil || !saInfo.Mode().IsRegular() {
		return errReport("sa_file is not a readable file")
	}
	if opts.MaxPackets != nil && *opts.MaxPackets <= 0 {
		return errReport("max_packets must be a positive number")
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 25
	}

	saBytes, readErr := os.ReadFile(opts.SAFile)
	if readErr != nil {
		return errReport("cannot read the SA file: " + readErr.Error())
	}
	sas, parseErr := extract.ParseSAFile(string(saBytes))
	if parseErr != nil {
		return errReport("cannot read the SA file: " + parseErr.Error())
	}

	res, decErr := extract.DecryptESP(ctx, filePath, sas, opts.DisplayFilter, opts.MaxPackets)
	if decErr != nil {
		return errReport(decErr.Error())
	}

	var innerSummary *InnerSummary
	innerWritten := 0
	tmpDir, tmpErr := os.MkdirTemp("", "sonic-esp-")
	if tmpErr == nil {
		defer func() { _ = os.RemoveAll(tmpDir) }()
		innerPCAP := filepath.Join(tmpDir, "inner.pcap")
		n, wErr := writeInnerPCAP(res.Inner, innerPCAP)
		if wErr == nil {
			innerWritten = n
		}
		if innerWritten > 0 {
			trueVal := true
			netRep := netorch.AnalyzeNetworkCapture(ctx, innerPCAP, netorch.Options{
				Detectors:  opts.Detectors,
				IncludeSIP: &trueVal,
				MaxItems:   maxItems,
			})
			innerSummary = buildInnerSummary(netRep)
		}
	}

	saRows := make([]SARow, 0, len(res.Stats))
	for _, st := range res.Stats {
		saRows = append(saRows, SARow{
			Src:        st.Src,
			Dst:        st.Dst,
			SPI:        st.SPI,
			Encryption: st.Encryption,
			Integrity:  st.Integrity,
			Packets:    st.Packets,
			Decrypted:  st.Decrypted,
			Tunnel:     st.Tunnel,
			Transport:  st.Transport,
			ICVGood:    st.ICVGood,
			ICVBad:     st.ICVBad,
		})
	}
	slices.SortStableFunc(saRows, func(a, b SARow) int {
		if c := cmp.Compare(a.Src, b.Src); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Dst, b.Dst); c != 0 {
			return c
		}
		return cmp.Compare(a.SPI, b.SPI)
	})

	issues := []model.Issue{}
	totalPkts, totalDec, sasDecrypting := 0, 0, 0
	for i := range saRows {
		saRows[i].Reason = saReason(saRows[i])
		sa := saRows[i]
		totalPkts += sa.Packets
		totalDec += sa.Decrypted
		if sa.Decrypted > 0 {
			sasDecrypting++
		}
		label := fmt.Sprintf("SA %s -> %s SPI %s", sa.Src, sa.Dst, sa.SPI)
		switch {
		case sa.Packets == 0:
			issues = append(issues, model.Issue{Severity: model.SeverityWarning, Code: "ESP_SA_NO_PACKETS", Message: label + ": " + *sa.Reason, Frames: []int{}})
		case sa.Decrypted == 0:
			issues = append(issues, model.Issue{Severity: model.SeverityError, Code: "ESP_SA_NOT_DECRYPTED", Message: label + ": " + *sa.Reason, Frames: []int{}})
		case sa.Decrypted < sa.Packets:
			issues = append(issues, model.Issue{Severity: model.SeverityWarning, Code: "ESP_SA_PARTIAL", Message: label + ": " + *sa.Reason, Frames: []int{}})
		}
	}
	warnings := res.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	for _, w := range warnings {
		issues = append(issues, model.Issue{
			Severity: model.SeverityError,
			Code:     "ESP_SA_TABLE_REFUSED",
			Message:  "tshark refused a row of the SA table: " + w,
			Frames:   []int{},
		})
	}

	present := totalPkts > 0 || len(sas) > 0
	issues = model.SortIssues(issues)
	if issues == nil {
		issues = []model.Issue{}
	}
	listedSAs, sasOmitted := model.Cap(saRows, maxItems)
	if listedSAs == nil {
		listedSAs = []SARow{}
	}
	var dispPtr *string
	if opts.DisplayFilter != "" {
		d := opts.DisplayFilter
		dispPtr = &d
	}

	return Report{
		Status:        "success",
		Schema:        ReportSchema,
		File:          filePath,
		OverallStatus: model.StatusFromIssues(issues, present),
		Verdict:       buildVerdict(saRows, totalPkts, totalDec, innerWritten, innerSummary),
		Capture: CaptureInfo{
			Tshark:                    tshark.VersionString(ctx, ""),
			SACount:                   len(sas),
			ESPPackets:                totalPkts,
			ESPDecrypted:              totalDec,
			InnerPacketsReconstructed: innerWritten,
			Warnings:                  warnings,
			DisplayFilter:             dispPtr,
			MaxPackets:                opts.MaxPackets,
		},
		Summary: Summary{
			SecurityAssociations: len(saRows),
			ESPPackets:           totalPkts,
			ESPDecrypted:         totalDec,
			SAsDecrypting:        sasDecrypting,
		},
		SecurityAssociations:        listedSAs,
		SecurityAssociationsOmitted: sasOmitted,
		InnerAnalysis:               innerSummary,
		Issues:                      issues,
		Limits:                      slices.Clone(Limits),
	}
}
