// Package qos implements ITU-T G.107 E-Model MOS calculation and RTP stream
// payload-type to codec mapping matching analyzers/rtp_mos_analysis.py.
package qos

import (
	"math"
	"strconv"

	"github.com/zombat/sonic/internal/model"
)

var ptCodecMap = map[string]string{
	"0":  "G.711",
	"8":  "G.711",
	"9":  "G.722",
	"18": "G.729",
	"97": "iLBC",
	"98": "Opus",
	"3":  "GSM",
	"4":  "G.723",
}

var codecBaseIe = map[string]float64{
	"G.711":   0,
	"G.722":   0,
	"G.729":   11,
	"Opus":    0,
	"iLBC":    5,
	"Unknown": 10,
}

// MapPayloadToCodec maps an RTP numeric payload type to the codec name used in E-Model scoring.
func MapPayloadToCodec(pt int) string {
	if c, ok := ptCodecMap[strconv.Itoa(pt)]; ok {
		return c
	}
	return "Unknown"
}

// CalculateEModelMOS computes the ITU-T G.107 E-Model MOS score rounded to 2 decimal places.
func CalculateEModelMOS(codec string, packetLossRate, avgJitterMs float64) float64 {
	const (
		ro = 93.2
		is = 1.41
		a  = 0.0
	)
	r := ro - is
	baseIe, ok := codecBaseIe[codec]
	if !ok {
		baseIe = 10
	}
	if packetLossRate > 0 {
		baseIe += 30.0 * math.Log10(1.0+15.0*packetLossRate/100.0)
	}
	if avgJitterMs > 20 {
		baseIe += (avgJitterMs - 20.0) / 10.0
	}
	r = r - baseIe + a

	var mos float64
	switch {
	case r < 0:
		mos = 1.0
	case r > 100:
		mos = 4.5
	default:
		mos = 1.0 + 0.035*r + 7e-6*r*(r-60.0)*(100.0-r)
	}
	if mos < 1.0 {
		mos = 1.0
	} else if mos > 5.0 {
		mos = 5.0
	}
	return model.Round(mos, 2)
}
