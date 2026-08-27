package xio

// FeatureACCEPTFD is set by fileopen on Unix. Classic ACCEPT-FD consumes a
// listening descriptor (systemd inetd / ExtraFiles). Windows has no POSIX fd
// passing model for this address; help hides it when false (VSOCK/UDPLITE).
var FeatureACCEPTFD bool
