// Package grpc manages pinned gNMI/gNOI/protobuf schema search paths for Wireshark.
package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ProtoPathVariable names the environment override for Wireshark protobuf schema paths.
const ProtoPathVariable = "SONIC_PROTO_PATH"

type protoPin struct {
	repo   string
	tag    string
	commit string
	src    string
	target string
	sha256 string
}

var pinnedProtoFiles = []protoPin{
	{"openconfig/gnmi", "v0.14.1", "8b7dd494c4f6ff517431965d662621d8884bad0f", "proto/gnmi/gnmi.proto", "github.com/openconfig/gnmi/proto/gnmi/gnmi.proto", "45abf90bfee289544e2430c8ce1b5b10e4f851736a508ddba54d3cf12e82f7b7"},
	{"openconfig/gnmi", "v0.14.1", "8b7dd494c4f6ff517431965d662621d8884bad0f", "proto/gnmi_ext/gnmi_ext.proto", "github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto", "b0e96bd0c540cf249512783ee5abeb3f0d05805115f18c7d714ac90316981e2e"},
	{"openconfig/gnoi", "v0.8.0", "3d3c7f196a957397bb73e3c84c1ec67bbabad0be", "types/types.proto", "github.com/openconfig/gnoi/types/types.proto", "f2cfcaf19623b93e1ce5c075bd745ea0b81e6b982f0752e9fb8297da2b85c12b"},
	{"openconfig/gnoi", "v0.8.0", "3d3c7f196a957397bb73e3c84c1ec67bbabad0be", "common/common.proto", "github.com/openconfig/gnoi/common/common.proto", "45d64bbd89fd952cee3a83ee5657a14d534f09089f1ccd3c5088bd268c457f13"},
	{"openconfig/gnoi", "v0.8.0", "3d3c7f196a957397bb73e3c84c1ec67bbabad0be", "system/system.proto", "github.com/openconfig/gnoi/system/system.proto", "fa5d4ff283af2178207dd94755ca5c901fd08a13ac44d28d8ae06a53cb8df30e"},
	{"openconfig/gnoi", "v0.8.0", "3d3c7f196a957397bb73e3c84c1ec67bbabad0be", "cert/cert.proto", "github.com/openconfig/gnoi/cert/cert.proto", "85d36865c7efbef71f93a68bc4720d84fcfaf14eaeb166b343916c8a94417e4d"},
	{"openconfig/gnoi", "v0.8.0", "3d3c7f196a957397bb73e3c84c1ec67bbabad0be", "file/file.proto", "github.com/openconfig/gnoi/file/file.proto", "9a2c133f0b745e5400ccb4c4ce0384e97854c38cb5445cd22dcde6414c01d971"},
	{"openconfig/gnoi", "v0.8.0", "3d3c7f196a957397bb73e3c84c1ec67bbabad0be", "healthz/healthz.proto", "github.com/openconfig/gnoi/healthz/healthz.proto", "dac77213f87900fded24f9ab93b1d9a740f1ef279a5741c70529fb028d071bc4"},
	{"protocolbuffers/protobuf", "v3.20.3", "fe271ab76f2ad2b2b28c10443865d2af21e27e0e", "src/google/protobuf/any.proto", "google/protobuf/any.proto", "1aa80cf90ddbd380b73b1422bae51d76d99b82a4cdf0b183f21a802f72aafe8b"},
	{"protocolbuffers/protobuf", "v3.20.3", "fe271ab76f2ad2b2b28c10443865d2af21e27e0e", "src/google/protobuf/descriptor.proto", "google/protobuf/descriptor.proto", "c05fcefb4de00db652f321ee62c1f463b0158a0589ba1abd26209707b965d011"},
	{"protocolbuffers/protobuf", "v3.20.3", "fe271ab76f2ad2b2b28c10443865d2af21e27e0e", "src/google/protobuf/duration.proto", "google/protobuf/duration.proto", "099047097e8fe73657b49ef67af914a7a686ac6154f9d872882708b5eb3db04c"},
	{"protocolbuffers/protobuf", "v3.20.3", "fe271ab76f2ad2b2b28c10443865d2af21e27e0e", "src/google/protobuf/timestamp.proto", "google/protobuf/timestamp.proto", "9489462cbd4eff7c013d10de596be38da1087c7824ea34357669bc21bf5c0800"},
	{"openconfig/gnmi", "v0.14.1", "8b7dd494c4f6ff517431965d662621d8884bad0f", "LICENSE", "LICENSES/openconfig-gnmi.LICENSE", "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"},
	{"openconfig/gnoi", "v0.8.0", "3d3c7f196a957397bb73e3c84c1ec67bbabad0be", "LICENSE", "LICENSES/openconfig-gnoi.LICENSE", "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1"},
	{"protocolbuffers/protobuf", "v3.20.3", "fe271ab76f2ad2b2b28c10443865d2af21e27e0e", "LICENSE", "LICENSES/protobuf.LICENSE", "6e5e117324afd944dcf67f36cf329843bc1a92229a8cd9bb573d7a83130fea7d"},
}

// Pins returns a copy of the expected SHA-256 digests keyed by relative proto target path.
func Pins() map[string]string {
	out := make(map[string]string, len(pinnedProtoFiles))
	for _, f := range pinnedProtoFiles {
		out[f.target] = f.sha256
	}
	return out
}

// DefaultProtoDir returns ~/.cache/sonic/grpc-protos.
func DefaultProtoDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".", ".cache", "sonic", "grpc-protos")
	}
	return filepath.Join(home, ".cache", "sonic", "grpc-protos")
}

// ResolveProtoPaths selects explicit paths, SONIC_PROTO_PATH entries, or DefaultProtoDir if present.
func ResolveProtoPaths(protoPaths []string, ignoreDefault bool) []string {
	if len(protoPaths) > 0 {
		out := make([]string, 0, len(protoPaths))
		for _, p := range protoPaths {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	if env := os.Getenv(ProtoPathVariable); env != "" {
		var out []string
		for _, p := range filepath.SplitList(env) {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	if !ignoreDefault {
		defDir := DefaultProtoDir()
		if info, err := os.Stat(defDir); err == nil && info.IsDir() {
			return []string{defDir}
		}
	}
	return []string{}
}

// FetchResult summarizes FetchProtos execution matching utils/grpc_protos.py.
type FetchResult struct {
	Status string   `json:"status"`
	Dir    string   `json:"dir,omitempty"`
	Files  []string `json:"files,omitempty"`
	Error  string   `json:"error,omitempty"`
	File   string   `json:"file,omitempty"`
}

// FetchProtos downloads pinned gNMI/gNOI/protobuf definitions into dest and verifies SHA-256 digests.
func FetchProtos(
	ctx context.Context,
	dest string,
	opener func(context.Context, string) ([]byte, error),
	pins map[string]string,
) FetchResult {
	if dest == "" {
		dest = DefaultProtoDir()
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return FetchResult{Status: "error", Error: err.Error()}
	}
	if opener == nil {
		opener = defaultProtoOpener
	}
	if pins == nil {
		pins = Pins()
	}

	written := make([]string, 0, len(pinnedProtoFiles))
	for _, entry := range pinnedProtoFiles {
		u := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", entry.repo, entry.commit, entry.src)
		data, err := opener(ctx, u)
		if err != nil {
			return FetchResult{Status: "error", Error: fmt.Sprintf("download failed: %T: %s", err, err), File: u}
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		if expected := pins[entry.target]; expected != "" && digest != expected {
			return FetchResult{
				Status: "error",
				File:   u,
				Error:  fmt.Sprintf("SHA-256 mismatch for %s: got %s, pinned %s", entry.target, digest, expected),
			}
		}
		if err := writeAtomic(filepath.Join(absDest, filepath.FromSlash(entry.target)), data); err != nil {
			return FetchResult{Status: "error", Error: err.Error(), File: u}
		}
		written = append(written, entry.target)
	}
	readme := fmt.Sprintf(
		"These files were downloaded by `sonic --fetch-grpc-protos` for Wireshark's protobuf\n"+
			"dissector, which S.O.N.I.C. points at this directory when it analyzes gRPC captures.\n"+
			"They are not part of S.O.N.I.C. and keep their own licenses (LICENSES/):\n"+
			"  github.com/openconfig/gnmi  %s (%s), Apache-2.0\n"+
			"  github.com/openconfig/gnoi  %s (%s), Apache-2.0\n"+
			"  google/protobuf             %s (%s), BSD-3-Clause\n",
		pinnedProtoFiles[0].tag, pinnedProtoFiles[0].commit,
		pinnedProtoFiles[2].tag, pinnedProtoFiles[2].commit,
		pinnedProtoFiles[8].tag, pinnedProtoFiles[8].commit,
	)
	if err := writeAtomic(filepath.Join(absDest, "README.txt"), []byte(readme)); err != nil {
		return FetchResult{Status: "error", Error: err.Error()}
	}
	return FetchResult{Status: "success", Dir: absDest, Files: written}
}

func defaultProtoOpener(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sonic-fetch-grpc-protos")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func writeAtomic(target string, data []byte) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".sonic-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
