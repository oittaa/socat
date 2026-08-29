//go:build darwin || windows

package netopen

// Darwin and others may lack SOCK_CLOEXEC on socket(2); newSocket uses CloseOnExec.
const sockCloexec = 0
