// Package extract decodes TShark capture streams into normalized S.O.N.I.C.
// packet records matching the Python extractor bit-for-bit.
package extract

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
)

const blake2bDigestSize = 8

var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var blake2bSigma = [12][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

// PayloadHash computes the 8-byte unkeyed RFC 7693 BLAKE2b digest of payload
// as a 16-character lowercase hex string, matching hashlib.blake2b(..., digest_size=8).
func PayloadHash(payload []byte) string {
	h := blake2bIV
	// Standard parameter block P[0]: fanout=1, depth=1, digest_size=8.
	h[0] ^= 0x01010000 ^ uint64(blake2bDigestSize)

	var offset uint64
	for len(payload) > 128 {
		offset += 128
		blake2bCompress(&h, payload[:128], offset, false)
		payload = payload[128:]
	}

	var block [128]byte
	copy(block[:], payload)
	offset += uint64(len(payload))
	blake2bCompress(&h, block[:], offset, true)

	var out [blake2bDigestSize]byte
	binary.LittleEndian.PutUint64(out[:], h[0])
	return hex.EncodeToString(out[:])
}

// blake2bCompress executes the 12-round RFC 7693 F compression function on a single 128-byte block.
func blake2bCompress(h *[8]uint64, block []byte, t uint64, last bool) {
	var m [16]uint64
	for i := range 16 {
		m[i] = binary.LittleEndian.Uint64(block[i*8 : i*8+8])
	}

	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], blake2bIV[:])
	v[12] ^= t
	if last {
		v[14] = ^v[14]
	}

	for r := range 12 {
		s := &blake2bSigma[r]
		blake2bMix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		blake2bMix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		blake2bMix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		blake2bMix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		blake2bMix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		blake2bMix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		blake2bMix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		blake2bMix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	for i := range 8 {
		h[i] ^= v[i] ^ v[i+8]
	}
}

// blake2bMix applies one RFC 7693 G quarter-round to state v.
func blake2bMix(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] = v[a] + v[b] + x
	v[d] = bits.RotateLeft64(v[d]^v[a], -32)
	v[c] = v[c] + v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -24)
	v[a] = v[a] + v[b] + y
	v[d] = bits.RotateLeft64(v[d]^v[a], -16)
	v[c] = v[c] + v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -63)
}
