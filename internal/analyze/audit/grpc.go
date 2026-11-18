// Package audit enriches cleartext audit reports with HPACK-decoded gRPC service names and metadata credentials.
package audit

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/model"
)

// AddGrpcFindings enriches an AuditReport in place when cleartext HTTP/2 flows are present.
func AddGrpcFindings(ctx context.Context, section *model.AuditReport, filePath, displayFilter string, maxPackets *int) {
	if section == nil || section.Status != "success" {
		return
	}
	hasH2 := false
	for _, s := range section.TCPSessions {
		if strings.HasPrefix(s.Protocol, "http2 (") {
			hasH2 = true
			break
		}
	}
	if !hasH2 {
		for _, v := range section.Violations {
			if strings.HasPrefix(v.Protocol, "http2 (") {
				hasH2 = true
				break
			}
		}
	}
	if !hasH2 {
		return
	}

	incTLS := false
	rep := grpc.AnalyzeCapture(ctx, filePath, grpc.Options{
		DisplayFilter:         displayFilter,
		MaxPackets:            maxPackets,
		MaxItems:              100,
		IncludeTLS:            &incTLS,
		IgnoreDefaultProtoDir: true,
	})
	if rep.Status != "success" {
		section.Grpc = &model.AuditGrpcSummary{Checked: false, Error: rep.Error}
		return
	}

	grpcPorts := make(map[string]map[string]bool)
	allServices := make(map[string]bool)
	for _, conn := range rep.Connections {
		if conn.Protocol == "grpc" && conn.Service != nil && *conn.Service != "" {
			set, ok := grpcPorts[*conn.Service]
			if !ok {
				set = make(map[string]bool)
				grpcPorts[*conn.Service] = set
			}
			for _, svc := range conn.Services {
				set[svc] = true
				allServices[svc] = true
			}
		}
	}

	renamed := make(map[string]string, len(grpcPorts))
	portServices := make(map[string][]string, len(grpcPorts))
	for port, svcs := range grpcPorts {
		oldName := fmt.Sprintf("http2 (%s)", port)
		newName := fmt.Sprintf("grpc (%s)", port)
		renamed[oldName] = newName
		portServices[newName] = slices.Sorted(maps.Keys(svcs))
	}

	for i := range section.Violations {
		if newName, ok := renamed[section.Violations[i].Protocol]; ok {
			section.Violations[i].Protocol = newName
			section.Violations[i].GrpcServices = portServices[newName]
		}
	}
	for i := range section.ByProtocol {
		if newName, ok := renamed[section.ByProtocol[i].Protocol]; ok {
			section.ByProtocol[i].Protocol = newName
			section.ByProtocol[i].GrpcServices = portServices[newName]
		}
	}
	for i := range section.TCPSessions {
		if newName, ok := renamed[section.TCPSessions[i].Protocol]; ok {
			section.TCPSessions[i].Protocol = newName
			section.TCPSessions[i].GrpcServices = portServices[newName]
		}
	}

	for oldName, newName := range renamed {
		section.Verdict = strings.ReplaceAll(section.Verdict, oldName, newName)
		for i := range section.Issues {
			section.Issues[i].Message = strings.ReplaceAll(section.Issues[i].Message, oldName, newName)
			if section.Issues[i].Protocol == oldName {
				section.Issues[i].Protocol = newName
			}
		}
	}

	creds := make([]model.AuditCredential, len(rep.Credentials))
	clearKeys := make(map[string]bool)
	for i, c := range rep.Credentials {
		creds[i] = model.AuditCredential{
			Flow: c.Flow, Service: c.Service, Key: c.Key, Cleartext: c.Cleartext,
			Transport: c.Transport, Requests: c.Requests, FirstFrame: c.FirstFrame,
			Frames: c.Frames, Value: c.Value,
		}
		if c.Cleartext {
			clearKeys[c.Key] = true
		}
	}
	section.Credentials = &creds

	svcsList := slices.Sorted(maps.Keys(allServices))
	if svcsList == nil {
		svcsList = []string{}
	}
	section.Grpc = &model.AuditGrpcSummary{
		Checked:     true,
		Connections: len(rep.Connections),
		RPCs:        rep.Summary.RPCs,
		Services:    svcsList,
	}

	for _, iss := range rep.Issues {
		if iss.Code == "CLEARTEXT_CREDENTIAL" {
			section.Issues = append(section.Issues, iss)
		}
	}
	if len(clearKeys) > 0 {
		section.Verdict += fmt.Sprintf("; credentials in cleartext gRPC metadata: %s (values masked)",
			strings.Join(slices.Sorted(maps.Keys(clearKeys)), ", "))
	}
}
