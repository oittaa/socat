//go:build darwin || windows

package netopen

// SOCK_CLOEXEC is unavailable; newSocket uses CloseOnExec.
const sockCloexec = 0
