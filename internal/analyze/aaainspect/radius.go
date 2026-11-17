// Package aaainspect RADIUS transaction grouping, RFC 3579 Message-Authenticator HMAC-MD5 checks, and issue reporting.
package aaainspect

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"strconv"
)

// RadiusCodes maps RADIUS code integers to RFC message names.
var RadiusCodes = map[int]string{
	1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
	4: "Accounting-Request", 5: "Accounting-Response", 11: "Access-Challenge",
	12: "Status-Server", 13: "Status-Client",
	40: "Disconnect-Request", 41: "Disconnect-ACK", 42: "Disconnect-NAK",
	43: "CoA-Request", 44: "CoA-ACK", 45: "CoA-NAK",
}

// RadiusAcctStatus maps Acct-Status-Type attribute values to labels.
var RadiusAcctStatus = map[int]string{
	1: "Start", 2: "Stop", 3: "Interim-Update", 7: "Accounting-On", 8: "Accounting-Off",
}

// radiusRawSide holds one raw RADIUS UDP payload keyed by packet code for Message-Authenticator checks.
type radiusRawSide struct {
	code int
	raw  []byte
}

// radiusTrack accumulates RADIUS transaction state prior to scrubbing _raw.
type radiusTrack struct {
	RadiusView
	t       *float64
	rawReq  *radiusRawSide
	rawResp *radiusRawSide
}

// MessageAuthenticator checks RFC 3579 section 3.2 Message-Authenticator over raw UDP payload.
// Returns "absent", "unchecked", "valid", or "invalid".
func MessageAuthenticator(raw []byte, secret *string, reqAuth []byte) string {
	if len(raw) < 20 {
		return "unchecked"
	}
	declaredLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if declaredLen < len(raw) {
		raw = raw[:declaredLen]
	}
	pos := 20
	offset := -1
	for pos+2 <= len(raw) {
		atype, alen := raw[pos], int(raw[pos+1])
		if alen < 2 || pos+alen > len(raw) {
			break
		}
		if atype == 80 && alen == 18 {
			offset = pos + 2
			break
		}
		pos += alen
	}
	if offset < 0 {
		return "absent"
	}
	if secret == nil || *secret == "" {
		return "unchecked"
	}
	data := make([]byte, len(raw))
	copy(data, raw)
	expected := make([]byte, 16)
	copy(expected, data[offset:offset+16])
	clear(data[offset : offset+16])
	if len(reqAuth) == 16 {
		copy(data[4:20], reqAuth)
	}
	mac := hmac.New(md5.New, []byte(*secret))
	mac.Write(data)
	return map[bool]string{true: "valid", false: "invalid"}[hmac.Equal(mac.Sum(nil), expected)]
}

// radiusExchanges groups extracted RADIUS rows by (client, server, id, kind) and verifies Message-Authenticator.
func radiusExchanges(rows []map[string]string, secret *string) []radiusTrack {
	type txKey struct {
		client, server string
		id             int
		kind           string
	}
	txMap := make(map[txKey]*radiusTrack)
	var order []txKey

	for _, row := range rows {
		code, ok := parseInt(firstVal(row, "radius.code"))
		if !ok {
			continue
		}
		rid, hasID := parseInt(firstVal(row, "radius.id"))
		idKey := -1
		var idPtr *int
		if hasID {
			idKey = rid
			idPtr = &rid
		}
		isAcct := code == 4 || code == 5
		isReq := code == 1 || code == 4
		clientPort, serverPort := "udp.dstport", "udp.srcport"
		clientDir, serverDir := "dst", "src"
		if isReq {
			clientPort, serverPort = "udp.srcport", "udp.dstport"
			clientDir, serverDir = "src", "dst"
		}
		client := endpoint(row, clientDir, clientPort)
		server := endpoint(row, serverDir, serverPort)
		kind := "auth"
		if isAcct {
			kind = "acct"
		}
		key := txKey{client: client, server: server, id: idKey, kind: kind}
		tx, exists := txMap[key]
		if !exists {
			fullKind := "auth"
			if isAcct {
				fullKind = "accounting"
			}
			tx = &radiusTrack{
				RadiusView: RadiusView{
					Client: client, Server: server, ID: idPtr, Kind: fullKind, Frames: []int{},
				},
			}
			txMap[key] = tx
			order = append(order, key)
		}
		if fr, ok := parseInt(firstVal(row, "frame.number")); ok && fr != 0 {
			tx.Frames = append(tx.Frames, fr)
		}
		if tx.t == nil {
			tv, _ := strconv.ParseFloat(firstVal(row, "frame.time_epoch"), 64)
			tx.t = &tv
		}
		if name := firstVal(row, "radius.User_Name"); name != "" && tx.Username == nil {
			tx.Username = &name
		}
		nas := firstVal(row, "radius.NAS_IP_Address")
		if nas == "" {
			nas = firstVal(row, "radius.NAS_Identifier")
		}
		if nas != "" && tx.NAS == nil {
			tx.NAS = &nas
		}
		if calling := firstVal(row, "radius.Calling_Station_Id"); calling != "" && tx.CallingStation == nil {
			tx.CallingStation = &calling
		}
		if acct, ok := parseInt(firstVal(row, "radius.Acct_Status_Type")); ok {
			lbl := RadiusAcctStatus[acct]
			if lbl == "" {
				lbl = strconv.Itoa(acct)
			}
			tx.AcctStatus = &lbl
		}
		if raw := decodeHexPayload(firstVal(row, "udp.payload")); len(raw) > 0 {
			if isReq && tx.rawReq == nil {
				tx.rawReq = &radiusRawSide{code: code, raw: raw}
			} else if !isReq && tx.rawResp == nil {
				tx.rawResp = &radiusRawSide{code: code, raw: raw}
			}
		}
		if v := firstVal(row, "radius.authenticator.valid"); v == "1" || v == "True" {
			b := true
			tx.AuthenticatorValid = &b
		}
		if v := firstVal(row, "radius.authenticator.invalid"); v == "1" || v == "True" {
			b := false
			tx.AuthenticatorValid = &b
		}
		if firstVal(row, "radius.User_Password") != "" || firstVal(row, "radius.CHAP_Password") != "" {
			tx.CredentialRecovered = true
		}
		codeName := RadiusCodes[code]
		if codeName == "" {
			codeName = strconv.Itoa(code)
		}
		if isReq {
			tx.RequestCode = &codeName
		} else {
			tx.ResponseCode = &codeName
		}
	}

	out := make([]radiusTrack, 0, len(order))
	for _, key := range order {
		tx := txMap[key]
		tx.Result = radiusResult(&tx.RadiusView)
		checkSide := func(side *radiusRawSide) *string {
			if side == nil {
				return nil
			}
			var state string
			if side.code == 1 || side.code == 12 {
				state = MessageAuthenticator(side.raw, secret, nil)
			} else if (side.code == 2 || side.code == 3 || side.code == 11) && tx.rawReq != nil && len(tx.rawReq.raw) >= 20 {
				state = MessageAuthenticator(side.raw, secret, tx.rawReq.raw[4:20])
			} else {
				s := MessageAuthenticator(side.raw, nil, nil)
				state = "unchecked"
				if s == "absent" {
					state = "absent"
				}
			}
			return &state
		}
		tx.MessageAuthenticator.Request = checkSide(tx.rawReq)
		tx.MessageAuthenticator.Response = checkSide(tx.rawResp)
		tx.rawReq = nil
		tx.rawResp = nil
		if tx.CredentialRecovered {
			m := "masked"
			tx.Credential = &m
		}
		out = append(out, *tx)
	}
	return out
}

// radiusResult maps request/response presence and RADIUS response code to an outcome token.
func radiusResult(tx *RadiusView) string {
	if tx.ResponseCode != nil {
		switch *tx.ResponseCode {
		case "Access-Accept":
			return "accept"
		case "Access-Reject":
			return "reject"
		case "Access-Challenge":
			return "challenge"
		}
	}
	if tx.Kind == "accounting" {
		if tx.ResponseCode != nil {
			return "accounted"
		}
		return "no_response"
	}
	if tx.RequestCode != nil {
		return "no_response"
	}
	return "orphan_response"
}
