package dtls13

import (
	"testing"
	"time"
)

func TestProbeTimeoutMeetsRFC8899(t *testing.T) {
	if probeTimeout < minProbeTimeout {
		t.Fatalf("probe timeout %s below RFC 8899 minimum %s", probeTimeout, minProbeTimeout)
	}
	if probeTimeout <= 15*time.Second {
		t.Fatalf("probe timeout %s is not larger than 15s", probeTimeout)
	}
	if probePace <= 0 {
		t.Fatal("probe pace must be positive")
	}
	if confirmTimer >= raiseTimer {
		t.Fatalf("confirm timer %s is not less than raise timer %s", confirmTimer, raiseTimer)
	}
	if raiseTimer != 600*time.Second {
		t.Fatalf("raise timer %s want 600s", raiseTimer)
	}
}
