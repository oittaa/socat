//go:build linux

package netopen

// Linux <linux/udp.h> / udplite(7). Classic xio-udplite.c (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same file) falls back to
// these when platform headers omit the macros.
const (
	udpliteSendCscov = 10
	udpliteRecvCscov = 11
)
