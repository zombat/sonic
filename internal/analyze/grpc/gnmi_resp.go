// Package grpc decodes gNMI, gNOI, and gRPC health response protobuf payloads.
package grpc

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zombat/sonic/internal/model"
)

// CapabilitiesResponse holds decoded gnmi.gNMI/Capabilities responses.
type CapabilitiesResponse struct {
	GnmiVersion        *string   `json:"gnmi_version"`
	SupportedEncodings []*string `json:"supported_encodings"`
	Models             int       `json:"models"`
	ModelNames         []*string `json:"model_names"`
}

// GetResponse holds decoded gnmi.gNMI/Get responses.
type GetResponse struct {
	Notifications int        `json:"notifications"`
	Updates       int        `json:"updates"`
	Error         *GnmiError `json:"error,omitempty"`
}

// SetResponse holds decoded gnmi.gNMI/Set responses.
type SetResponse struct {
	Results int            `json:"results"`
	Ops     map[string]int `json:"ops"`
	Error   *GnmiError     `json:"error,omitempty"`
}

// SubscribeMsgDecoded holds one decoded gnmi.gNMI/Subscribe response packet.
type SubscribeMsgDecoded struct {
	Notification *bool      `json:"notification,omitempty"`
	Updates      *int       `json:"updates,omitempty"`
	Deletes      *int       `json:"deletes,omitempty"`
	SyncResponse *bool      `json:"sync_response,omitempty"`
	Error        *GnmiError `json:"error,omitempty"`
}

// SubscribeResponseSummary aggregates streamed gnmi.gNMI/Subscribe responses for one RPC.
type SubscribeResponseSummary struct {
	Messages      int         `json:"messages"`
	Notifications int         `json:"notifications"`
	Updates       int         `json:"updates"`
	Deletes       int         `json:"deletes"`
	SyncResponse  bool        `json:"sync_response"`
	Errors        []GnmiError `json:"errors,omitempty"`
}

// HealthResponse holds grpc.health.v1.Health Check/Watch responses.
type HealthResponse struct {
	ServingStatus string `json:"serving_status"`
}

// TimeResponse holds gnoi.system.System/Time responses.
type TimeResponse struct {
	TargetTimeEpochS float64  `json:"target_time_epoch_s"`
	SkewS            *float64 `json:"skew_s,omitempty"`
}

// DecodedResponse represents one decoded or aggregated RPC response variant.
type DecodedResponse struct {
	Capabilities *CapabilitiesResponse
	Get          *GetResponse
	Set          *SetResponse
	SubscribeMsg *SubscribeMsgDecoded
	SubscribeSum *SubscribeResponseSummary
	Health       *HealthResponse
	Time         *TimeResponse
}

// Empty reports whether DecodedResponse holds any decoded fields.
func (d *DecodedResponse) Empty() bool {
	return d == nil || (d.Capabilities == nil && d.Get == nil && d.Set == nil &&
		d.SubscribeMsg == nil && d.SubscribeSum == nil && d.Health == nil && d.Time == nil)
}

// MarshalJSON encodes whichever response variant is populated matching gnmi_decode.py.
func (d DecodedResponse) MarshalJSON() ([]byte, error) {
	switch {
	case d.Capabilities != nil:
		return json.Marshal(d.Capabilities)
	case d.Get != nil:
		return json.Marshal(d.Get)
	case d.Set != nil:
		return json.Marshal(d.Set)
	case d.SubscribeSum != nil:
		return json.Marshal(d.SubscribeSum)
	case d.SubscribeMsg != nil:
		return json.Marshal(d.SubscribeMsg)
	case d.Health != nil:
		return json.Marshal(d.Health)
	case d.Time != nil:
		return json.Marshal(d.Time)
	default:
		return []byte("{}"), nil
	}
}

// DecodeResponse extracts troubleshooting fields from one gNMI, gNOI, or health response payload.
func DecodeResponse(method string, message []byte, captureTime *float64) (*DecodedResponse, error) {
	service, rpc := splitMethod(method)
	fields, err := ParseFields(message)
	if err != nil {
		return nil, err
	}
	switch {
	case service == "gnmi.gNMI" && rpc == "Capabilities":
		return decodeCapResp(fields)
	case service == "gnmi.gNMI" && rpc == "Get":
		return decodeGetResp(fields)
	case service == "gnmi.gNMI" && rpc == "Set":
		return decodeSetResp(fields)
	case service == "gnmi.gNMI" && rpc == "Subscribe":
		return decodeSubResp(fields)
	case service == "grpc.health.v1.Health" && (rpc == "Check" || rpc == "Watch"):
		return &DecodedResponse{
			Health: &HealthResponse{
				ServingStatus: enumName(HealthStatus, oneInt(fields, 1, 0)),
			},
		}, nil
	case service == "gnoi.system.System" && rpc == "Time":
		tf, ok := oneField(fields, 1)
		if !ok {
			return &DecodedResponse{}, nil
		}
		sec := model.Round(float64(tf.Varint)/1e9, 6)
		tr := &TimeResponse{TargetTimeEpochS: sec}
		if captureTime != nil && *captureTime != 0 {
			skew := model.Round(float64(tf.Varint)/1e9-*captureTime, 3)
			tr.SkewS = &skew
		}
		return &DecodedResponse{Time: tr}, nil
	default:
		return &DecodedResponse{}, nil
	}
}

func decodeCapResp(fields []ProtoField) (*DecodedResponse, error) {
	models := allFields(fields, 1)
	names := make([]*string, 0, min(len(models), MaxList))
	for i := 0; i < len(models) && i < MaxList; i++ {
		if models[i].Wire != 2 {
			return nil, errors.New("expected bytes for ModelData")
		}
		mfs, err := ParseFields(models[i].Bytes)
		if err != nil {
			return nil, err
		}
		namePtr := fieldText(oneField(mfs, 1))
		verPtr := fieldText(oneField(mfs, 3))
		if verPtr != nil && *verPtr != "" {
			n := ""
			if namePtr != nil {
				n = *namePtr
			}
			full := fmt.Sprintf("%s %s", n, *verPtr)
			names = append(names, &full)
		} else {
			names = append(names, namePtr)
		}
	}
	encs, err := packedVarints(allFields(fields, 2))
	if err != nil {
		return nil, err
	}
	encNames := make([]*string, len(encs))
	for i, e := range encs {
		val := e
		encNames[i] = EncodingName(&val)
	}
	return &DecodedResponse{
		Capabilities: &CapabilitiesResponse{
			GnmiVersion:        fieldText(oneField(fields, 3)),
			SupportedEncodings: encNames,
			Models:             len(models),
			ModelNames:         names,
		},
	}, nil
}

func decodeGetResp(fields []ProtoField) (*DecodedResponse, error) {
	notes := allFields(fields, 1)
	updates := 0
	for _, n := range notes {
		if n.Wire != 2 {
			return nil, errors.New("expected bytes for Notification")
		}
		u, _, err := notificationCounts(n.Bytes)
		if err != nil {
			return nil, err
		}
		updates += u
	}
	gErr, err := parseGnmiError(fields, 2)
	if err != nil {
		return nil, err
	}
	return &DecodedResponse{
		Get: &GetResponse{
			Notifications: len(notes),
			Updates:       updates,
			Error:         gErr,
		},
	}, nil
}

func decodeSetResp(fields []ProtoField) (*DecodedResponse, error) {
	ops := make(map[string]int)
	total := 0
	for _, res := range allFields(fields, 2) {
		if res.Wire != 2 {
			return nil, errors.New("expected bytes for UpdateResult")
		}
		rfs, err := ParseFields(res.Bytes)
		if err != nil {
			return nil, err
		}
		opName := UpdateOps[oneInt(rfs, 4, 0)]
		if opName == "" {
			opName = "INVALID"
		}
		ops[opName]++
		total++
	}
	gErr, err := parseGnmiError(fields, 3)
	if err != nil {
		return nil, err
	}
	return &DecodedResponse{
		Set: &SetResponse{
			Results: total,
			Ops:     ops,
			Error:   gErr,
		},
	}, nil
}

func decodeSubResp(fields []ProtoField) (*DecodedResponse, error) {
	sub := &SubscribeMsgDecoded{}
	hasAny := false
	if upd, ok := oneBytes(fields, 1); ok {
		u, d, err := notificationCounts(upd)
		if err != nil {
			return nil, err
		}
		t := true
		sub.Notification = &t
		sub.Updates = &u
		sub.Deletes = &d
		hasAny = true
	}
	if sr := oneInt(fields, 3, 0); sr != 0 {
		t := true
		sub.SyncResponse = &t
		hasAny = true
	}
	gErr, err := parseGnmiError(fields, 4)
	if err != nil {
		return nil, err
	}
	if gErr != nil {
		sub.Error = gErr
		hasAny = true
	}
	if !hasAny {
		return &DecodedResponse{}, nil
	}
	return &DecodedResponse{SubscribeMsg: sub}, nil
}
