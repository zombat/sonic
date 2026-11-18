// Package extract runs tshark -T pdml streaming extraction over HTTP/2 and protobuf layers.
package extract

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/tshark"
)

// HTTP2Header represents a single decoded (and potentially masked) HPACK header entry.
type HTTP2Header struct {
	Name       string
	Value      *string
	Masked     bool
	Credential bool
}

// HTTP2Frame holds normalized metadata and capped payload from one HTTP/2 frame in PDML.
type HTTP2Frame struct {
	Type           string
	TypeCode       int
	StreamID       int
	Length         int
	Flags          int
	EndStream      bool
	EndHeaders     bool
	Headers        []HTTP2Header
	HeaderListSize int
	DecodeFailed   bool
	Data           []byte
	DataLen        int
	ErrorCode      *int
	Settings       map[string]*int
	Ack            bool
	Opaque         string
	LastStreamID   *int
	DebugData      *string
	Increment      int
}

// ProtobufField stores an allowlisted dissected protobuf field and display value.
type ProtobufField struct {
	Field string
	Value string
}

// ProtobufMsg summarizes a Wireshark-dissected protobuf message in a PDML packet.
type ProtobufMsg struct {
	MessageType *string
	Path        *string
	Direction   *string
	Fields      []ProtobufField
}

// HTTP2Packet aggregates all HTTP/2 frames and protobuf records decoded from one packet.
type HTTP2Packet struct {
	N         int
	T         float64
	TCPStream int
	Src       string
	Dst       string
	Sport     *int
	Dport     *int
	TLS       bool
	Frames    []HTTP2Frame
	Protobuf  []ProtobufMsg
}

// HTTP2Extraction holds streamed HTTP/2 packets along with in-memory secret scrubbing sets and status.
type HTTP2Extraction struct {
	Packets        []HTTP2Packet
	SecretValues   map[string]bool
	IdentityValues map[string]bool
	Status         map[string]string
}

type pdmlPacket struct {
	Protos []pdmlProto `xml:"proto"`
}

type pdmlProto struct {
	Name     string      `xml:"name,attr"`
	Showname string      `xml:"showname,attr"`
	Fields   []pdmlField `xml:"field"`
}

type pdmlField struct {
	Name     string      `xml:"name,attr"`
	Show     *string     `xml:"show,attr"`
	Showname string      `xml:"showname,attr"`
	Value    *string     `xml:"value,attr"`
	Fields   []pdmlField `xml:"field"`
}

// ProtobufOptions builds tshark preferences enabling protobuf directory UAT search and hf fields.
func ProtobufOptions(protoPaths []string) []string {
	var opts []string
	for _, p := range protoPaths {
		quoted := strings.ReplaceAll(strings.ReplaceAll(p, `\`, `\\`), `"`, `\"`)
		opts = append(opts, "-o", fmt.Sprintf(`uat:protobuf_search_paths:"%s","TRUE"`, quoted))
	}
	if len(opts) > 0 {
		opts = append(opts, "-o", "protobuf.pbf_as_hf:TRUE")
	}
	return opts
}

// IterHTTP2Packets runs tshark -T pdml over http2 frames and returns parsed HTTP2Extraction.
func IterHTTP2Packets(
	ctx context.Context,
	filePath string,
	decodeAs []string,
	keylogFile string,
	protoPaths []string,
	displayFilter string,
	maxPackets *int,
	outOfOrder bool,
) (*HTTP2Extraction, error) {
	ext := &HTTP2Extraction{
		SecretValues:   make(map[string]bool),
		IdentityValues: make(map[string]bool),
		Status:         make(map[string]string),
	}
	flt := "http2"
	if displayFilter != "" {
		flt = fmt.Sprintf("(%s) && http2", displayFilter)
	}
	capturePath, cleanupCapture := tshark.PrepareCapturePath(filePath)
	defer cleanupCapture()

	args := []string{"-n", "-r", capturePath}
	args = append(args, decodeAs...)
	if outOfOrder {
		args = append(args, "-o", "tcp.reassemble_out_of_order:TRUE")
	}
	if keylogFile != "" {
		stagedKeylog, cleanupKeylog := tshark.PrepareCapturePath(keylogFile)
		defer cleanupKeylog()
		args = append(args, "-o", "tls.keylog_file:"+stagedKeylog)
	}
	args = append(args, ProtobufOptions(protoPaths)...)
	top := "ip ipv6 tcp tls http2"
	if len(protoPaths) > 0 {
		top += " protobuf"
	}
	args = append(args, "-Y", flt, "-T", "pdml", "-J", top)
	if maxPackets != nil && *maxPackets > 0 {
		args = append(args, "-c", strconv.Itoa(*maxPackets))
	}

	cmd := exec.CommandContext(ctx, tshark.DefaultBinary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("tshark pdml pipe: %w", err)
	}
	var stderr limitedTailBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tshark pdml: %w", err)
	}

	dec := xml.NewDecoder(stdout)
	produced := 0
	for {
		tok, derr := dec.Token()
		if derr == io.EOF {
			break
		}
		if derr != nil {
			ext.Status["parse_error"] = derr.Error()
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "packet" {
			continue
		}
		var pkt pdmlPacket
		if uerr := dec.DecodeElement(&pkt, &se); uerr != nil {
			ext.Status["parse_error"] = uerr.Error()
			break
		}
		if parsed := packetFromPDML(&pkt, ext); parsed != nil {
			produced++
			ext.Packets = append(ext.Packets, *parsed)
		}
	}

	waitErr := cmd.Wait()
	ext.Status["packets"] = strconv.Itoa(produced)
	ext.Status["stderr"] = stderr.rawTail()
	if cmd.ProcessState != nil {
		ext.Status["returncode"] = strconv.Itoa(cmd.ProcessState.ExitCode())
	}
	if waitErr != nil && produced == 0 {
		return nil, fmt.Errorf("tshark failed (exit %s): %s", ext.Status["returncode"], stderr.String())
	}
	return ext, nil
}

func pdmlFirst(fields []pdmlField, name string) *pdmlField {
	for i := range fields {
		if fields[i].Name == name {
			return &fields[i]
		}
		if found := pdmlFirst(fields[i].Fields, name); found != nil {
			return found
		}
	}
	return nil
}

func pdmlShow(fields []pdmlField, name string) *string {
	f := pdmlFirst(fields, name)
	if f == nil {
		return nil
	}
	return f.Show
}

func strDeref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
