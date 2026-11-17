package extract

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func buildTestPCAPNGBlock(bo binary.ByteOrder, btype uint32, body []byte) []byte {
	pad := (4 - (len(body) % 4)) % 4
	total := uint32(12 + len(body) + pad)
	buf := bytes.NewBuffer(make([]byte, 0, total))
	_ = binary.Write(buf, bo, btype)
	_ = binary.Write(buf, bo, total)
	buf.Write(body)
	buf.Write(make([]byte, pad))
	_ = binary.Write(buf, bo, total)
	return buf.Bytes()
}

func buildTestDSB(bo binary.ByteOrder, stype uint32, secretText string) []byte {
	raw := []byte(secretText)
	body := bytes.NewBuffer(make([]byte, 0, 8+len(raw)))
	_ = binary.Write(body, bo, stype)
	_ = binary.Write(body, bo, uint32(len(raw)))
	body.Write(raw)
	return buildTestPCAPNGBlock(bo, PCAPNGDSB, body.Bytes())
}

func buildTestSHB(bo binary.ByteOrder) []byte {
	body := bytes.NewBuffer(make([]byte, 0, 16))
	_ = binary.Write(body, bo, ByteOrderMagic)
	_ = binary.Write(body, bo, uint16(1))
	_ = binary.Write(body, bo, uint16(0))
	_ = binary.Write(body, bo, int64(-1))
	return buildTestPCAPNGBlock(bo, PCAPNGSection, body.Bytes())
}

func TestLabelsByRandomAndKeyLogLabels(t *testing.T) {
	t.Parallel()
	r1 := strings.Repeat("a1", 32)
	r2 := strings.Repeat("b2", 32)
	lines := []string{
		"# comment",
		"RSA Session-ID:abc Master-Key:def",
		"UNKNOWN_LABEL " + r1 + " supersecret1",
		"CLIENT_RANDOM short supersecret2",
		"CLIENT_RANDOM " + strings.ToUpper(r1) + " supersecret3",
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET " + r2 + " supersecret4",
		"SERVER_HANDSHAKE_TRAFFIC_SECRET " + r2 + " supersecret5",
	}
	got := LabelsByRandom(lines)
	if len(got) != 2 || !got[r1]["CLIENT_RANDOM"] || len(got[r2]) != 2 {
		t.Fatalf("unexpected labels map: %#v", got)
	}

	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "sslkeylog.txt")
	if err := os.WriteFile(keyPath, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := KeyLogLabels(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromFile, got) {
		t.Fatalf("KeyLogLabels mismatch: got %#v want %#v", fromFile, got)
	}
	if _, err := KeyLogLabels(filepath.Join(tmp, "missing")); err == nil {
		t.Fatal("expected error for missing keylog file")
	}
}

func TestPCAPNGSecretsAndMissingLabels(t *testing.T) {
	t.Parallel()
	r1 := strings.Repeat("c3", 32)
	r2 := strings.Repeat("d4", 32)
	tmp := t.TempDir()

	// Non-pcapng file returns nil, nil.
	pcapPath := filepath.Join(tmp, "plain.pcap")
	if err := os.WriteFile(pcapPath, []byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := PCAPNGSecrets(pcapPath); err != nil || res != nil {
		t.Fatalf("expected (nil, nil) on non-pcapng, got (%v, %v)", res, err)
	}
	if _, err := PCAPNGSecrets(filepath.Join(tmp, "missing.pcapng")); err == nil {
		t.Fatal("expected error on missing file")
	}

	// Build multi-section pcapng (LE section + DSB + non-TLS DSB + BE section + DSB + truncated trailing block).
	var buf bytes.Buffer
	buf.Write(buildTestSHB(binary.LittleEndian))
	buf.Write(buildTestDSB(binary.LittleEndian, DSBTLS, "CLIENT_RANDOM "+r1+" s1\n"))
	buf.Write(buildTestDSB(binary.LittleEndian, 0x11223344, "IGNORED "+r2+" s2\n"))
	buf.Write(buildTestSHB(binary.BigEndian))
	buf.Write(buildTestDSB(binary.BigEndian, DSBTLS, "CLIENT_TRAFFIC_SECRET_0 "+r2+" s3\nSERVER_TRAFFIC_SECRET_0 "+r2+" s4\n"))
	// Append damaged block length to confirm graceful break.
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0, 0, 0, 0})

	ngPath := filepath.Join(tmp, "secrets.pcapng")
	if err := os.WriteFile(ngPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := PCAPNGSecrets(ngPath)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Blocks != 2 || !res.Labels[r1]["CLIENT_RANDOM"] || !res.Labels[r2]["CLIENT_TRAFFIC_SECRET_0"] {
		t.Fatalf("unexpected PCAPNGSecrets result: %#v", res)
	}

	if got := MissingLabels(map[string]bool{"CLIENT_TRAFFIC_SECRET_0": true}, "TLS1.3"); len(got) != 3 {
		t.Fatalf("TLS 1.3 missing count: got %v", got)
	}
	if got := MissingLabels(map[string]bool{}, "TLS1.2"); !reflect.DeepEqual(got, []string{"CLIENT_RANDOM"}) {
		t.Fatalf("TLS 1.2 missing: got %v", got)
	}
	if got := MissingLabels(map[string]bool{"CLIENT_RANDOM": true}, "TLS1.2"); len(got) != 0 {
		t.Fatalf("TLS 1.2 present: got %v", got)
	}
	if got := MissingLabels(nil, ""); len(got) != 0 {
		t.Fatalf("empty version: got %v", got)
	}
}
