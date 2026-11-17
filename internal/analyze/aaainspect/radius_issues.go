// Package aaainspect RADIUS issue emission and hex payload decoding helpers.
package aaainspect

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// appendRadiusIssues emits RADIUS reject, unanswered, bad-authenticator, Blast-RADIUS, and recovery findings.
func appendRadiusIssues(radius []radiusTrack, secretGiven bool, issues *[]model.Issue, creds *[]CredentialRow) {
	for _, e := range radius {
		idStr := "None"
		if e.ID != nil {
			idStr = strconv.Itoa(*e.ID)
		}
		label := fmt.Sprintf("%s -> %s id %s", e.Client, e.Server, idStr)
		var frames []int
		if len(e.Frames) > 0 {
			frames = e.Frames[:1]
		}
		userLabel := "a user"
		if e.Username != nil && *e.Username != "" {
			userLabel = *e.Username
		}
		if e.Result == "reject" {
			iss := model.MakeIssue(model.SeverityWarning, "AAA_ACCESS_REJECT",
				fmt.Sprintf("%s: %s was rejected (Access-Reject)", label, userLabel), frames)
			iss.Username = e.Username
			*issues = append(*issues, iss)
		} else if e.Result == "no_response" && e.Kind == "auth" {
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "AAA_NO_RESPONSE",
				fmt.Sprintf("%s: Access-Request for %s got no response", label, userLabel), frames))
		}
		if secretGiven && e.ResponseCode != nil && e.AuthenticatorValid != nil && !*e.AuthenticatorValid {
			*issues = append(*issues, model.MakeIssue(model.SeverityError, "RADIUS_BAD_AUTHENTICATOR",
				fmt.Sprintf("%s: the %s response authenticator did not validate against the shared secret: the key is wrong, or the packet was altered", label, *e.ResponseCode), frames))
		}
		for _, pair := range []struct {
			state *string
			name  *string
		}{
			{e.MessageAuthenticator.Request, e.RequestCode},
			{e.MessageAuthenticator.Response, e.ResponseCode},
		} {
			if pair.state != nil && *pair.state == "invalid" {
				nameStr := "None"
				if pair.name != nil {
					nameStr = *pair.name
				}
				*issues = append(*issues, model.MakeIssue(model.SeverityError, "RADIUS_BAD_MESSAGE_AUTHENTICATOR",
					fmt.Sprintf("%s: the %s Message-Authenticator did not verify against the shared secret: the key is wrong, or the packet was altered", label, nameStr), frames))
			}
		}
		if e.Kind == "auth" && e.ResponseCode != nil &&
			(*e.ResponseCode == "Access-Accept" || *e.ResponseCode == "Access-Reject" || *e.ResponseCode == "Access-Challenge") &&
			e.MessageAuthenticator.Response != nil && *e.MessageAuthenticator.Response == "absent" {
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "RADIUS_NO_MESSAGE_AUTHENTICATOR",
				fmt.Sprintf("%s: the %s carried no Message-Authenticator: such a response can be forged by Blast-RADIUS (CVE-2024-3596); have the server send it on every response and the client require it", label, *e.ResponseCode), frames))
		}
		if e.CredentialRecovered {
			*creds = append(*creds, CredentialRow{
				Protocol: "radius", Flow: e.Client + " -> " + e.Server, Username: e.Username, Kind: "User-Password", Value: "masked",
			})
			iss := model.MakeIssue(model.SeverityInfo, "AAA_CREDENTIAL_RECOVERED",
				fmt.Sprintf("%s: the User-Password for %s was decrypted with the shared secret (value masked): anyone with the secret and the capture can read it", label, userLabel), frames)
			iss.Username = e.Username
			*issues = append(*issues, iss)
		}
	}
}

// decodeHexPayload parses optional colon-separated hex tshark byte fields.
func decodeHexPayload(raw string) []byte {
	if raw == "" {
		return nil
	}
	clean := strings.ReplaceAll(raw, ":", "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil
	}
	return b
}
