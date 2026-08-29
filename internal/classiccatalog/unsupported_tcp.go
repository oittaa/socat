package classiccatalog

// unsupportedTCP are classic GROUP_TCP TYPE_INT OFUNC_SOCKOPT names whose
// kernel objects are structures. The public integer syntax cannot represent
// them safely, so they are not advertised and are not an implementation
// backlog. Do not add fake integer setters or a structure syntax.
//
// tcp-info: Linux TCP_INFO is get-only struct tcp_info. Classic still
// models it as TYPE_INT (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same option table).
//
// tcp-md5sig: Linux TCP_MD5SIG needs struct tcp_md5sig. Classic still
// models it as TYPE_INT (same SHAs). md5sig is not this option: it is the
// documented TCP_MD5SUM spelling in foreign.go / docs_only.go.
var unsupportedTCP = map[string]string{
	"tcp-info":   "TCP_INFO is get-only structured state; public TYPE_INT syntax cannot represent it (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"info":       "alias of tcp-info; get-only struct, rejected, not advertised",
	"tcp-md5sig": "TCP_MD5SIG needs struct tcp_md5sig; public TYPE_INT syntax cannot represent it safely (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
}
