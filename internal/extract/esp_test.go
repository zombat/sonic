package extract

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func strRef(s string) *string { return &s }

func testSAFileText() string {
	aesKey := "0x000102030405060708090a0b0c0d0e0f"
	sha1Key := "0x000102030405060708090a0b0c0d0e0f10111213"
	sha256Key := "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	gcmKey := "0x000102030405060708090a0b0c0d0e0fdeadbeef"
	return strings.Join([]string{
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00001001\nencryption: aes-cbc\nencryption_key: " + aesKey + "\nintegrity: hmac-sha1-96\nintegrity_key: " + sha1Key,
		"src: 198.51.100.2\ndst: 198.51.100.1\nspi: 0x00001002\nencryption: aes-gcm\nencryption_key: " + gcmKey,
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00002001\nencryption: aes-cbc\nencryption_key: " + aesKey + "\nintegrity: hmac-sha256-128\nintegrity_key: " + sha256Key,
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00003001\nencryption: aes-cbc\nencryption_key: " + aesKey + "\nintegrity: hmac-sha256-128\nintegrity_key: " + sha256Key,
		"src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00004001\nencryption: aes-gcm\nencryption_key: " + gcmKey,
	}, "\n\n") + "\n"
}

func testXfrmText() string {
	return "src 198.51.100.1 dst 198.51.100.2\n" +
		"\tproto esp spi 0x00001001 reqid 1 mode tunnel\n" +
		"\tenc cbc(aes) 0x000102030405060708090a0b0c0d0e0f\n" +
		"\tauth-trunc hmac(sha1) 0x000102030405060708090a0b0c0d0e0f10111213 96\n" +
		"src 198.51.100.2 dst 198.51.100.1\n" +
		"\tproto esp spi 0x00001002 reqid 2 mode tunnel\n" +
		"\taead rfc4106(gcm(aes)) 0x000102030405060708090a0b0c0d0e0fdeadbeef 128\n"
}

func TestESPSAParsingAndUAT(t *testing.T) {
	sas, err := ParseSAFile(testSAFileText())
	if err != nil || len(sas) != 5 {
		t.Fatalf("ParseSAFile expected 5 SAs, got %d err=%v", len(sas), err)
	}
	if sas[1].Integrity != nil {
		t.Fatalf("expected nil integrity for omitted key in SA file, got %v", *sas[1].Integrity)
	}

	// Alternate separators (---, [sa], =, quotes) and delegated xfrm dump.
	alt := "# header comment\n[sa]\nsource = '10.0.0.1'\ndest = \"10.0.0.2\"\nspi = 256\nproto: IPv4\ncipher: aes-cbc\nkey: AA:BB CC DD\nauth: hmac-sha256-128\nauth_key: 0x1122\n---\nignored no sep\n"
	altSAs, err := ParseSAFile(alt)
	if err != nil || len(altSAs) != 1 || altSAs[0].Protocol != "IPv4" {
		t.Fatalf("ParseSAFile alt failed: %+v err=%v", altSAs, err)
	}
	row, err := SAUATRow(altSAs[0])
	if err != nil || !strings.Contains(row, `"0x00000100","AES-CBC [RFC3602]","0xaabbccdd","HMAC-SHA-256-128 [RFC4868]","0x1122"`) {
		t.Fatalf("unexpected SAUATRow: %s err=%v", row, err)
	}

	xfrmSAs, err := ParseSAFile(testXfrmText())
	if err != nil || len(xfrmSAs) != 2 || xfrmSAs[1].Integrity == nil || *xfrmSAs[1].Integrity != "none" {
		t.Fatalf("ParseXfrmState via ParseSAFile failed: %+v err=%v", xfrmSAs, err)
	}
	xfrmV6, err := ParseSAFile("src 2001:db8::1 dst 2001:db8::2\n\tproto esp spi 0x10\n\taead rfc4106(gcm(aes)) 0x001122 96\nsrc 2001:db8::2 dst 2001:db8::1\n\tproto esp spi 0x20\n\taead rfc4106(gcm(aes)) 0x001122 64\n")
	if err != nil || len(xfrmV6) != 2 || xfrmV6[0].Protocol != "IPv6" || *xfrmV6[0].Encryption != "aes-gcm-12" || *xfrmV6[1].Encryption != "aes-gcm-8" {
		t.Fatalf("IPv6 xfrm parse failed: %+v err=%v", xfrmV6, err)
	}

	// Secret safety: invalid key error never echoes any substring of the secret input.
	secretBad := "MY_SUPER_SECRET_NONHEX_KEY"
	if _, err := hexKey(secretBad); err == nil || strings.Contains(err.Error(), "SUPER_SECRET") {
		t.Fatalf("hexKey error leaked key or failed to reject: %v", err)
	}
	if _, err := ParseSAFile("src: 1.1.1.1\n"); err == nil {
		t.Fatal("expected missing fields error in ParseSAFile")
	}
	if _, err := ParseXfrmState("src 1.1.1.1 dst 2.2.2.2\n"); err == nil {
		t.Fatal("expected error in ParseXfrmState without spi")
	}
	if got, err := CanonicalSPI("deadbeef"); err != nil || got != "0xdeadbeef" {
		t.Fatalf("CanonicalSPI hex failed: %q err=%v", got, err)
	}
	if _, err := CanonicalSPI("999999999999"); err == nil {
		t.Fatal("expected overflow error from CanonicalSPI")
	}
	if _, err := SAUATRow(EspSA{Src: "1.1.1.1", Dst: "2.2.2.2", SPI: "1", Encryption: strRef("bad-cipher")}); err == nil {
		t.Fatal("expected unknown encryption algorithm error")
	}
	if _, err := SAUATRow(EspSA{Src: "1.1.1.1", Dst: "2.2.2.2", SPI: "1", Integrity: strRef("bad-auth")}); err == nil {
		t.Fatal("expected unknown integrity algorithm error")
	}
	if got := nullICVBytes(EspSA{Encryption: strRef("null"), Integrity: strRef("hmac-sha256-128")}); got != 16 {
		t.Fatalf("expected 16-byte null ICV, got %d", got)
	}
}

func TestESPPacketReconstructionAndDecrypt(t *testing.T) {
	// ESPTrailer positive and rejection cases.
	if p, nh, ok := ESPTrailer([]byte{'h', 'i', 1, 2, 2, 6}); !ok || string(p) != "hi" || nh != 6 {
		t.Fatalf("ESPTrailer valid mismatch: p=%q nh=%d ok=%v", p, nh, ok)
	}
	for _, bad := range [][]byte{{1}, {1, 5, 6}, {1, 3, 2, 6}, {1, 2, 2, 250}} {
		if _, _, ok := ESPTrailer(bad); ok {
			t.Fatalf("expected ESPTrailer rejection on %x", bad)
		}
	}

	// Transport reconstruction for IPv4 (RFC 1071 checksum == 0 across header) and IPv6.
	v4 := transportIPPacket("198.51.100.1", "198.51.100.2", 6, []byte{0, 80, 0, 81})
	if len(v4) != 24 || v4[9] != 6 || ipv4Checksum(v4[:20]) != 0 {
		t.Fatalf("invalid reconstructed IPv4 packet: len=%d csum=0x%04x", len(v4), ipv4Checksum(v4[:20]))
	}
	v6 := transportIPPacket("2001:db8::1", "2001:db8::2", 17, []byte{1, 2, 3, 4})
	if len(v6) != 44 || (v6[0]>>4) != 6 || binary.BigEndian.Uint16(v6[4:6]) != 4 || v6[6] != 17 {
		t.Fatalf("invalid reconstructed IPv6 packet: len=%d", len(v6))
	}
	if transportIPPacket("bad-ip", "1.1.1.1", 6, nil) != nil {
		t.Fatal("expected nil for invalid transport IP")
	}

	// Tunnel innerIPPacket validation for IPv4 & IPv6.
	tun4 := make([]byte, 24)
	tun4[0] = 0x45
	binary.BigEndian.PutUint16(tun4[2:4], 24)
	if innerIPPacket(tun4, 4) == nil {
		t.Fatal("expected valid IPv4 tunnel packet")
	}
	tun6 := make([]byte, 48)
	tun6[0] = 0x60
	binary.BigEndian.PutUint16(tun6[4:6], 8)
	if innerIPPacket(tun6, 41) == nil || innerIPPacket(tun4, 41) != nil {
		t.Fatal("IPv6 tunnel innerIPPacket mismatch")
	}

	// Live DecryptESP on testdata/fixtures/esp_tunnel.pcap.
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)

	sas, err := ParseSAFile(testSAFileText())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := DecryptESP(ctx, filepath.Join("testdata", "fixtures", "esp_tunnel.pcap"), sas, "", nil)
	if err != nil {
		t.Fatalf("DecryptESP failed: %v", err)
	}
	if len(res.Inner) != 7 || len(res.Warnings) != 0 {
		t.Fatalf("expected 7 inner packets & 0 warnings, got %d packets, warnings=%v", len(res.Inner), res.Warnings)
	}
	// Wrong key still attempts decryption and detects ICV_BAD on row processing.
	wrongSAS, _ := ParseSAFile("src: 198.51.100.1\ndst: 198.51.100.2\nspi: 0x00001001\nencryption: aes-cbc\nencryption_key: 0xffffffffffffffffffffffffffffffff\nintegrity: hmac-sha1-96\nintegrity_key: 0xffffffffffffffffffffffffffffffffffffffff\n")
	wrongRes, err := DecryptESP(ctx, filepath.Join("testdata", "fixtures", "esp_tunnel.pcap"), wrongSAS, "esp.spi == 0x00001001", nil)
	if err != nil {
		t.Fatalf("DecryptESP wrong key failed: %v", err)
	}
	st := wrongRes.Stats[ESPKey{Src: "198.51.100.1", Dst: "198.51.100.2", SPI: "0x00001001"}]
	if st == nil || st.ICVBad != 2 || st.Decrypted != 0 {
		t.Fatalf("expected 2 ICVBad & 0 decrypted on wrong key, got %+v", st)
	}
	// Synthetic processESPRow for dummy NextHeader=59 and NULL encryption with ICV trimming.
	dummyHex := hex.EncodeToString([]byte{'o', 'k', 0, 59})
	nullWithICV := hex.EncodeToString(append([]byte{0x45, 0, 0, 20}, append(make([]byte, 16), append([]byte{0, 4}, make([]byte, 12)...)...)...))
	stats := map[ESPKey]*ESPStatsRow{
		{Src: "10.0.0.1", Dst: "10.0.0.2", SPI: "0x00000001"}: {Src: "10.0.0.1", Dst: "10.0.0.2", SPI: "0x00000001", nullICV: 12},
	}
	var synthInner []DecryptedInnerPacket
	processESPRow(map[string]string{"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "esp.spi": "1", "esp.decrypted_data": dummyHex}, &synthInner, stats)
	processESPRow(map[string]string{"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2", "esp.spi": "1", "esp.decrypted_data": nullWithICV}, &synthInner, stats)
	if stats[ESPKey{Src: "10.0.0.1", Dst: "10.0.0.2", SPI: "0x00000001"}].Decrypted != 2 || len(synthInner) != 1 {
		t.Fatalf("expected synthetic dummy + nullICV decryption count 2, got %+v inner=%d", stats[ESPKey{Src: "10.0.0.1", Dst: "10.0.0.2", SPI: "0x00000001"}], len(synthInner))
	}
}
