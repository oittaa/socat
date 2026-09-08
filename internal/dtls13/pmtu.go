package dtls13

import (
	"errors"
	"time"
)

const (
	// Handshake fragment floor after EMSGSIZE / unanswered flights. This is
	// not an RFC network-MTU minimum.
	minPathMTU       = 256
	maxMTUReductions = 8

	// RFC 8899 BASE_PLPMTU recommendation for IPv4, and this stack's default dtls-mtu.
	defaultPLPMTU = 1200

	// RFC 8899 PROBE_TIMER: MUST NOT be below 1s; SHOULD be larger than 15s.
	minProbeTimeout = time.Second
	probeTimeout    = 16 * time.Second
	// After an ack or loss, wait before another probe. RFC 8899 requires at
	// least one RTT when probes are not congestion-controlled. DTLS application
	// data has no ACK/RTT estimator.
	probePace = time.Second
	// RFC 8899 PMTU_RAISE_TIMER. Expiry restarts search; it does not restore the ceiling.
	raiseTimer = 600 * time.Second
	// DTLS application data has no ACKs. Confirm the working size while the
	// path is in use. Must be less than raiseTimer.
	confirmTimer = 60 * time.Second

	maxMTUDiff       = 20
	maxLostMTUProbes = 3
	maxSearchProbes  = 24
	maxConfirmFails  = 3
	invalidProbeSize = -1

	rrcCookieLen   = 8
	rrcMessageLen  = 1 + rrcCookieLen
	defaultAEADTag = 16
)

var (
	errProbeDisabled = errProbe("unfragmented MTU probes unavailable")
	errProbePending  = errProbe("MTU probe already outstanding")
	errProbeBusy     = errProbe("MTU probe deferred")
	errProbeSize     = errProbe("invalid MTU probe size")
	errProbeTooBig   = errProbe("MTU probe rejected by transport")
)

type probeError string

func errProbe(s string) probeError { return probeError(s) }

func (e probeError) Error() string { return "dtls: " + string(e) }

// IsDatagramTooLarge reports an oversized datagram rejected before transmission.
// A retry must use a smaller MaxDatagramSize. The underlying transport error,
// if any, remains available through errors.Is/As.
func IsDatagramTooLarge(err error) bool {
	var rejected *datagramSizeError
	return errors.Is(err, ErrDatagramTooLarge) || errors.As(err, &rejected)
}

type datagramSizeError struct{ error }

func (e *datagramSizeError) Unwrap() error { return e.error }

func datagramOverhead(cidLen, aeadTag int) int {
	if cidLen < 0 {
		cidLen = 0
	}
	if aeadTag < 0 {
		aeadTag = 0
	}
	return 1 + cidLen + unifiedSeqLen + unifiedLengthLen + 1 + aeadTag
}

func rrcProbeOverhead(cidLen, aeadTag int) int {
	return datagramOverhead(cidLen, aeadTag) + rrcMessageLen
}

func rrcProbePadding(datagramSize, cidLen, aeadTag int) (int, error) {
	overhead := rrcProbeOverhead(cidLen, aeadTag)
	if datagramSize < overhead {
		return 0, errProbeSize
	}
	pad := datagramSize - overhead
	if rrcMessageLen+pad > maxContent {
		return 0, errRecordOverflow
	}
	innerLen := rrcMessageLen + 1 + pad
	if innerLen+aeadTag > maxCiphertext {
		return 0, errRecordOverflow
	}
	return pad, nil
}

func (s *session) recordTagLen() int {
	w := s.epochs.write[s.currentWriteEpoch()]
	if w != nil && w.keys != nil {
		return w.keys.aead.Overhead()
	}
	return defaultAEADTag
}

func (s *session) mtuCeiling() int {
	if s.handshake == nil || s.handshake.config == nil {
		return defaultPLPMTU
	}
	return s.handshake.config.MTU
}

func (s *session) effectiveMTU() int {
	if s.working.pathMTU > 0 {
		return min(s.working.pathMTU, s.mtuCeiling())
	}
	return s.mtuCeiling()
}

func (s *session) reduceHandshakeMTU(tooBig int) bool {
	current := s.effectiveMTU()
	if current <= minPathMTU || s.working.reductions >= maxMTUReductions {
		return false
	}
	next := current / 2
	if tooBig > minPathMTU {
		if capped := tooBig - 1; capped < next {
			next = capped
		}
	}
	if next < minPathMTU {
		next = minPathMTU
	}
	if next >= current {
		return false
	}
	s.working.pathMTU = next
	s.working.reductions++
	return true
}

func (s *session) setWorkingMTU(n int) {
	if n <= 0 {
		return
	}
	n = min(n, s.mtuCeiling())
	if n < minPathMTU {
		n = minPathMTU
	}
	prev := s.effectiveMTU()
	if n <= prev {
		return
	}
	s.working.pathMTU = n
	s.working.reductions = 0
}
