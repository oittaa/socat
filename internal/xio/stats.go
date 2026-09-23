package xio

import (
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

// printStats writes STATISTICS lines (forced to Info on a clone, plus the
// experimental warning). Tests grep the substring STATISTICS.
func printStats(log *logx.Logger, st relay.Stats, l2r, r2l bool, started bool) {
	if log == nil {
		return
	}
	if !started {
		log.Warningf("transfer engine not yet started, statistics not available")
		return
	}
	if !l2r && !r2l {
		l2r, r2l = true, true
	}
	log.Warningf("statistics are experimental")
	statsLog := log.Clone()
	if statsLog.Level() < logx.Info {
		statsLog.SetLevel(logx.Info)
	}
	bw := statDigits(max(st.BlocksLR, st.BlocksRL))
	dw := statDigits(max(st.BytesLR, st.BytesRL))
	if l2r {
		statsLog.Infof("STATISTICS: left to right: %*d packets(s), %*d byte(s)",
			bw, st.BlocksLR, dw, st.BytesLR)
	}
	if r2l {
		statsLog.Infof("STATISTICS: right to left: %*d packets(s), %*d byte(s)",
			bw, st.BlocksRL, dw, st.BytesRL)
	}
}

// PrintLiveStats is SIGUSR1: live transfer if any, else last, else not started.
func PrintLiveStats(log *logx.Logger) {
	if ts := relay.LiveTrackers(); len(ts) > 0 {
		for _, t := range ts {
			printStats(log, t.Snapshot(), t.LeftToRight, t.RightToLeft, true)
		}
		return
	}
	printLastStats(log)
}

// PrintExitStats prints --statistics after Run if no session already printed.
func PrintExitStats(g *Global) {
	if g == nil || !g.Options().Statistics {
		return
	}
	if g.statsAlreadyPrinted() {
		return
	}
	printLastStats(g.Log)
}

// printLastStats is --statistics on exit.
func printLastStats(log *logx.Logger) {
	t := relay.LastTracker()
	if t == nil {
		printStats(log, relay.Stats{}, true, true, false)
		return
	}
	printStats(log, t.Snapshot(), t.LeftToRight, t.RightToLeft, true)
}

func statDigits(n uint64) int {
	d := 1
	for n >= 10 {
		d++
		n /= 10
	}
	return d
}
