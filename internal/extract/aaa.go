// Package extract handles TACACS+ and RADIUS tshark extraction with private tmpfs key storage.
package extract

import (
	"context"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/wsconfig"
)

// AAAFieldSep separates repeated field values within a single RADIUS or TACACS+ row.
const AAAFieldSep = "\x1f"

// RadiusFields lists the tshark fields extracted for every RADIUS frame.
var RadiusFields = []string{
	"frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
	"udp.srcport", "udp.dstport", "radius.code", "radius.id",
	"radius.User_Name", "radius.User_Password", "radius.CHAP_Password", "radius.State",
	"radius.NAS_IP_Address", "radius.NAS_Identifier", "radius.Calling_Station_Id", "radius.Called_Station_Id",
	"radius.Acct_Status_Type", "radius.Acct_Session_Id", "radius.Reply_Message",
	"radius.authenticator.valid", "radius.authenticator.invalid", "radius.Message_Authenticator",
	"udp.payload",
}

// TacacsFields lists the tshark fields extracted for every TACACS+ frame.
var TacacsFields = []string{
	"frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
	"tcp.srcport", "tcp.dstport", "tacplus.session_id", "tacplus.type", "tacplus.seqno", "tacplus.flags",
	"tacplus.authen_action", "tacplus.privilege_level", "tacplus.authentication_type", "tacplus.service",
	"tacplus.user", "tacplus.auth_password", "tacplus.body_authen_rep.status", "tacplus.body_authen_rep.server_msg",
	"tacplus.body_authen_req_cont.user", "tacplus.body_author_rep.auth_status", "tacplus.body_acct.status",
	"tacplus.acct.flags",
}

// RadiusSecretFields names RADIUS fields whose values represent recovered credentials.
var RadiusSecretFields = []string{"radius.User_Password", "radius.CHAP_Password"}

// TacacsSecretFields names TACACS+ fields whose values represent recovered credentials.
var TacacsSecretFields = []string{"tacplus.auth_password", "tacplus.body_authen_req_cont.user"}

// ExtractAAA runs Wireshark RADIUS and TACACS+ dissection using temporary preferences
// for tacplus.key and radius.shared_secret, returning raw rows and in-memory recovered secrets.
func ExtractAAA(
	ctx context.Context,
	filePath string,
	tacacsKey, radiusSecret *string,
	displayFilter string,
	maxPackets *int,
) ([]map[string]string, []map[string]string, map[string]bool, error) {
	prefs := make(map[string]string)
	if tacacsKey != nil && *tacacsKey != "" {
		prefs["tacplus.key"] = *tacacsKey
	}
	if radiusSecret != nil && *radiusSecret != "" {
		prefs["radius.shared_secret"] = *radiusSecret
		prefs["radius.validate_authenticator"] = "TRUE"
	}

	var radiusRows, tacacsRows []map[string]string
	err := wsconfig.WithConfig(prefs, nil, func(configDir string) error {
		env := wsconfig.Env(configDir)
		run := func(proto string, fields []string, out *[]map[string]string) error {
			flt := proto
			if displayFilter != "" {
				flt = fmt.Sprintf("(%s) && (%s)", displayFilter, proto)
			}
			_, err := streamTsharkFields(ctx, filePath, nil, flt, fields, AAAFieldSep, maxPackets, env, func(row map[string]string) error {
				*out = append(*out, row)
				return nil
			})
			return err
		}
		if err := run("radius", RadiusFields, &radiusRows); err != nil {
			return err
		}
		return run("tacplus", TacacsFields, &tacacsRows)
	})
	if err != nil {
		return nil, nil, nil, err
	}

	secrets := make(map[string]bool)
	collectSecrets := func(rows []map[string]string, names []string) {
		for _, row := range rows {
			for _, name := range names {
				for _, val := range strings.Split(row[name], AAAFieldSep) {
					if len(val) >= 3 {
						secrets[val] = true
					}
				}
			}
		}
	}
	collectSecrets(radiusRows, RadiusSecretFields)
	collectSecrets(tacacsRows, TacacsSecretFields)
	return radiusRows, tacacsRows, secrets, nil
}
