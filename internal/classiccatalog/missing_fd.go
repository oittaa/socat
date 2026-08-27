package classiccatalog

// FD options other than the ioctl family (see missing_ioctl.go).
// cloexec is implemented on Unix (GROUP_FD, PH_LATE, OFUNC_FCNTL F_SETFD
// FD_CLOEXEC). Windows hides the name (help_windows.go hideOpt) and rejects
// it at apply (ClassMustAdvertise + hideOpt, like ioctl).
var expectedMissingFD = map[string]Gap{}
