package classiccatalog

// PARENT signal policy for EXEC children. sighup/sigint/sigquit are
// implemented on Unix (GROUP_PARENT, PH_LATE, OFUNC_SIGNAL). Windows hides
// the names (help_windows.go hideOpt) like dash/setpgid.
var expectedMissingParent = map[string]Gap{}
