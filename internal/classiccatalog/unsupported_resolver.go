package classiccatalog

// unsupportedResolver is documented libc resolver / res_state spellings this
// port rejects instead of mutating process-global resolver state. They must
// not appear in ImplementationBacklog and must not be advertised as honored.
//
// Classic baseline: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba
// xio-ip.c xio_res_init temporarily overwrites process-global _res (opts,
// retrans, retry) for one address open, then restores it. Official master
// af5388c898c7bb60997935aee93c223deba60c4a is unchanged. Go cannot reproduce
// those libc res_state semantics per address without a custom DNS client, and
// this port never mutates net.DefaultResolver or libc _res.
//
// Implemented per-address instead: res-nsaddr (custom Dial), res-usevc
// (TCP-only via Resolver.Dial; =0 restores UDP-then-TCP), and getaddrinfo AI_V4MAPPED /
// AI_ALL / AI_PASSIVE / AI_ADDRCONFIG. res-aaonly / res-primary stay foreign
// (WITH_AA_ONLY / WITH_RES_PRIMARY).
var unsupportedResolver = map[string]string{
	"res-debug":      "RES_DEBUG mutates process-global _res; this port never mutates net.DefaultResolver or libc _res (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"res-defnames":   "RES_DEFNAMES mutates process-global _res; not reproducible per address in Go without a custom DNS client",
	"defnames":       "alias of res-defnames; rejected (does not mutate _res)",
	"res-dnsrch":     "RES_DNSRCH mutates process-global _res; not reproducible per address in Go without a custom DNS client",
	"dnsrch":         "alias of res-dnsrch; rejected (does not mutate _res)",
	"res-igntc":      "RES_IGNTC mutates process-global _res; Go's resolver already follows truncated UDP with TCP",
	"igntc":          "alias of res-igntc; rejected (does not mutate _res)",
	"res-recurse":    "RES_RECURSE mutates process-global _res; not reproducible per address in Go without a custom DNS client",
	"recurse":        "alias of res-recurse; rejected (does not mutate _res)",
	"res-stayopen":   "RES_STAYOPEN mutates process-global _res; not reproducible per address in Go without a custom DNS client",
	"stayopen":       "alias of res-stayopen; rejected (does not mutate _res)",
	"res-retrans":    "undocumented _res.retrans; mutating process-global retry timing is not reproduced per address",
	"res-maxretrans": "alias of res-retrans; rejected (does not mutate _res)",
	"retrans":        "alias of res-retrans; rejected (does not mutate _res)",
	"res-retry":      "undocumented _res.retry; mutating process-global retry count is not reproduced per address",
	"res-maxretry":   "alias of res-retry; rejected (does not mutate _res)",
}
