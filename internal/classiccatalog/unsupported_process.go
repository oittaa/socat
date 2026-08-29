package classiccatalog

// unsupportedProcess are classic GROUP_PROCESS privilege and root-directory
// spellings. Credentials and the process root are process-wide; changing
// them from a session goroutine would affect every session. They stay
// rejected and undocumented in help (README Unsupported / security-related).
// Do not implement them without process isolation.
//
// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same option table.
var unsupportedProcess = map[string]string{
	"chroot":            "process-wide chroot from a session goroutine would affect every session (README Unsupported / security-related)",
	"chroot-early":      "process-wide chroot-early from a session goroutine would affect every session (README Unsupported / security-related)",
	"setgid":            "process-wide setgid from a session goroutine would affect every session (README Unsupported / security-related)",
	"setgid-early":      "process-wide setgid-early from a session goroutine would affect every session (README Unsupported / security-related)",
	"setuid":            "process-wide setuid from a session goroutine would affect every session (README Unsupported / security-related)",
	"setuid-early":      "process-wide setuid-early from a session goroutine would affect every session (README Unsupported / security-related)",
	"substuser":         "process-wide substuser from a session goroutine would affect every session (README Unsupported / security-related)",
	"su":                "alias of substuser; process-wide, rejected, not advertised",
	"substuser-delayed": "process-wide substuser-delayed from a session goroutine would affect every session (README Unsupported / security-related)",
	"su-d":              "alias of substuser-delayed; process-wide, rejected, not advertised",
	"substuser-early":   "process-wide substuser-early from a session goroutine would affect every session (README Unsupported / security-related)",
	"su-e":              "alias of substuser-early; process-wide, rejected, not advertised",
}
