//go:build darwin

package relay

import "testing"

// TestWaitReadableAndWritableMaskedDestCloseAfterReady closes the destination
// after waitReadableAndWritable has masked it (Events=0). Darwin poll does not
// register kqueue filters for Events=0, so the waiting poll will not report
// the closed fd; the 0-timeout confirmation after a wait timeout must.
func TestWaitReadableAndWritableMaskedDestCloseAfterReady(t *testing.T) {
	runMaskedDestCloseAfterReady(t, poll)
}
