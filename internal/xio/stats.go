package xio

import (
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

// PrintStats writes classic WITH_STATS lines (forced to Info, plus the
// experimental warning). Tests grep the substring STATISTICS.
func PrintStats(log *logx.Logger, st relay.Stats, l2r, r2l bool, started bool) {
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
	old := log.Level()
	if old < logx.Info {
		log.SetLevel(logx.Info)
		defer log.SetLevel(old)
	}
	bw := statDigits(max(st.BlocksLR, st.BlocksRL))
	dw := statDigits(max(st.BytesLR, st.BytesRL))
	if l2r {
		log.Infof("STATISTICS: left to right: %*d packets(s), %*d byte(s)",
			bw, st.BlocksLR, dw, st.BytesLR)
	}
	if r2l {
		log.Infof("STATISTICS: right to left: %*d packets(s), %*d byte(s)",
			bw, st.BlocksRL, dw, st.BytesRL)
	}
}

// PrintLiveStats is SIGUSR1: live transfer if any, else last, else not started.
func PrintLiveStats(log *logx.Logger) {
	if ts := relay.LiveTrackers(); len(ts) > 0 {
		for _, t := range ts {
			PrintStats(log, t.Snapshot(), t.LeftToRight, t.RightToLeft, true)
		}
		return
	}
	PrintLastStats(log)
}

// PrintExitStats prints --statistics after Run if no session already printed.
func PrintExitStats(g *Global) {
	if g == nil || !g.Statistics || g.Log == nil {
		return
	}
	if g.statsAlreadyPrinted() {
		return
	}
	PrintLastStats(g.Log)
}

// PrintLastStats is --statistics on exit.
func PrintLastStats(log *logx.Logger) {
	t := relay.LastTracker()
	if t == nil {
		PrintStats(log, relay.Stats{}, true, true, false)
		return
	}
	PrintStats(log, t.Snapshot(), t.LeftToRight, t.RightToLeft, true)
}

func statDigits(n uint64) int {
	d := 1
	for n >= 10 {
		d++
		n /= 10
	}
	return d
}
