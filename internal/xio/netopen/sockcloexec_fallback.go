//go:build darwin

package netopen

// SOCK_CLOEXEC is unavailable; newSocket uses closeOnExec.
const sockCloexec = 0
