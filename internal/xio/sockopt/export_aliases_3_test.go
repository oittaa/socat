//go:build linux && !mips && !mipsle && !mips64 && !mips64le

package sockopt

// Test aliases for unexported socket-option names.
const OwnerIoctlFIOGETOWN = ownerIoctlFIOGETOWN
const OwnerIoctlFIOSETOWN = ownerIoctlFIOSETOWN
