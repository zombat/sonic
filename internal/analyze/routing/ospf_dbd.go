// Package routing OSPFv2 EXSTART/EXCHANGE DBD stall detection.
package routing

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// databaseExchange evaluates OSPF EXSTART/EXCHANGE progress and MTU/DBD-loss causes.
func (a *OspfAnalyzer) databaseExchange(ra, rb *ospfRouterState, exch map[int]int, ctx model.Context, issues *[]model.Issue) *OSPFDatabaseExchange {
	ab := a.dbds[addrDirKey{src: ra.address, dst: rb.address}]
	ba := a.dbds[addrDirKey{src: rb.address, dst: ra.address}]
	if len(ab) == 0 && len(ba) == 0 {
		return nil
	}
	label := ra.rid + " <-> " + rb.rid
	sa := buildDBDSide(ab, ba, ra, ctx)
	sb := buildDBDSide(ba, ab, rb, ctx)

	progressed := sa.NonInitialDBDSent > 0 || sb.NonInitialDBDSent > 0
	lsa := (exch[3] + exch[4] + exch[5]) > 0
	state := "exstart"
	if progressed {
		state = "exchange_or_later"
	}
	if lsa {
		state = "loading_or_full"
	}

	var stuckPtr *string
	repeatedInit := max(sa.InitialDBDSent, sb.InitialDBDSent) >= 3
	if !lsa && !progressed && repeatedInit {
		s := "exstart"
		stuckPtr = &s
	} else if !lsa && progressed && (len(sa.UnacknowledgedSequence) > 0 || len(sb.UnacknowledgedSequence) > 0 || repeatedInit) {
		s := "exchange"
		stuckPtr = &s
	}

	var causePtr *string
	if stuckPtr != nil {
		stuck := *stuckPtr
		cause := dbdStuckCause(sa, sb)
		causePtr = &cause

		var frames []int
		frames = append(frames, tailFrames(sa.Frames, 3)...)
		frames = append(frames, tailFrames(sb.Frames, 3)...)
		*issues = append(*issues, model.MakeIssue(
			model.SeverityError, "OSPF_"+strings.ToUpper(stuck)+"_STUCK",
			fmt.Sprintf("OSPF adjacency %s is stuck in %s: %s sent %d DBD(s), %s sent %d, and the exchange never progressed; cause: %s",
				label, strings.ToUpper(stuck), sa.Router, sa.DBDSent, sb.Router, sb.DBDSent, cause),
			frames,
		))
		if lastEntry, ok := latestDBD(ab, ba); ok {
			a.events = append(a.events, ospfEvent{
				kind: "dbd_stuck", t: lastEntry.t, frame: lastEntry.n,
				detail: fmt.Sprintf("OSPF %s stuck in %s", label, strings.ToUpper(stuck)),
			})
		}
	}

	return &OSPFDatabaseExchange{
		StateHint:       state,
		Stuck:           stuckPtr,
		Cause:           causePtr,
		Sides:           []OSPFDBDSide{sa, sb},
		LSAExchangeSeen: lsa,
	}
}

// buildDBDSide summarizes one router's transmitted DBDs and unacknowledged sequence numbers.
func buildDBDSide(dbds, other []ospfDBDEntry, sender *ospfRouterState, ctx model.Context) OSPFDBDSide {
	var initCnt, nonInitCnt int
	seqs := make(map[uint32]int)
	var seqOrd []uint32
	echoed := make(map[uint32]bool)
	for _, d := range other {
		if (d.flags&0x04) == 0 && d.seq != nil {
			echoed[*d.seq] = true
		}
	}
	frames := []int{}
	var firstT, lastT *float64
	var mtu *int
	if len(dbds) > 0 {
		firstT = ctx.Rel(&dbds[0].t)
		lastT = ctx.Rel(&dbds[len(dbds)-1].t)
		mtu = dbds[0].mtu
	}
	for i, d := range dbds {
		if i < 10 {
			frames = append(frames, d.n)
		}
		if (d.flags & 0x04) != 0 {
			initCnt++
		} else {
			nonInitCnt++
			if d.seq != nil {
				if _, exists := seqs[*d.seq]; !exists {
					seqOrd = append(seqOrd, *d.seq)
				}
				seqs[*d.seq]++
			}
		}
	}
	unack := make(map[string]int)
	for _, seq := range seqOrd {
		if cnt := seqs[seq]; cnt >= 3 && !echoed[seq] {
			unack[strconv.FormatUint(uint64(seq), 10)] = cnt
		}
	}
	return OSPFDBDSide{
		Router:                 sender.rid,
		DBDSent:                len(dbds),
		InitialDBDSent:         initCnt,
		NonInitialDBDSent:      nonInitCnt,
		MTU:                    mtu,
		UnacknowledgedSequence: unack,
		FirstT:                 firstT,
		LastT:                  lastT,
		Frames:                 frames,
	}
}

// dbdStuckCause classifies MTU mismatch, mtu-ignore=0 stall, or generic DBD loss across two sides.
func dbdStuckCause(sa, sb OSPFDBDSide) string {
	var mtuPairs []string
	mtuSet := make(map[int]bool)
	hasZeroMTU := false
	for _, side := range []OSPFDBDSide{sa, sb} {
		if side.MTU != nil {
			mtuPairs = append(mtuPairs, fmt.Sprintf("%s=%d", side.Router, *side.MTU))
			mtuSet[*side.MTU] = true
			if *side.MTU == 0 {
				hasZeroMTU = true
			}
		}
	}
	switch {
	case len(mtuSet) > 1:
		return fmt.Sprintf("interface MTU mismatch in the DBDs (%s): the router with the smaller MTU drops the larger router's DBDs", strings.Join(mtuPairs, ", "))
	case hasZeroMTU:
		return "one side advertises MTU 0 (mtu-ignore) and the exchange still stalls: DBDs are being lost"
	default:
		return "DBDs are not acknowledged with the same MTU on both sides: unicast between the neighbors lost or filtered, duplicate router IDs, or one side cannot send large packets"
	}
}

// latestDBD finds the chronologically last DBD packet across both directions.
func latestDBD(ab, ba []ospfDBDEntry) (ospfDBDEntry, bool) {
	var last ospfDBDEntry
	hasLast := false
	for _, list := range [][]ospfDBDEntry{ab, ba} {
		for _, d := range list {
			if !hasLast || d.t > last.t {
				last = d
				hasLast = true
			}
		}
	}
	return last, hasLast
}
