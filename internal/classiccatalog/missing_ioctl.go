package classiccatalog

// Generic ioctl family (PR I) is implemented on Unix including Darwin
// (GROUP_FD, PH_FD): ioctl, ioctl-void, ioctl-int, ioctl-intp, ioctl-bin,
// ioctl-string. Windows hides the names (help_windows.go hideOpt) and
// rejects them at apply (ClassMustAdvertise + hideOpt, like sctp-nodelay).
var expectedMissingIOCTL = map[string]Gap{}
