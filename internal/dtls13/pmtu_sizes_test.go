package dtls13

import (
	"testing"
	"time"
)

func TestMTUSizeContract(t *testing.T) {
	if minPathMTU == ipv4MinPLPMTU || minPathMTU == ipv6MinPLPMTU || minPathMTU == ipv4MinReassemblyPLPMTU {
		t.Fatalf("handshake floor %d collided with an RFC PLPMTU", minPathMTU)
	}
	if ipv4MinPLPMTU != 40 || ipv6MinPLPMTU != 1232 || ipv4MinReassemblyPLPMTU != 548 {
		t.Fatalf("UDP-payload RFC mins: ipv4=%d ipv6=%d reassembly=%d", ipv4MinPLPMTU, ipv6MinPLPMTU, ipv4MinReassemblyPLPMTU)
	}
	if ipPacketSize(ipv4MinPLPMTU, false) != ipv4MinIPPacket || ipPacketSize(ipv6MinPLPMTU, true) != ipv6MinIPPacket {
		t.Fatal("IP conversion drifted from RFC 8899 MIN_PLPMTU")
	}
	if ipPacketSize(ipv4MinReassemblyPLPMTU, false) != ipv4MinReassemblyIP {
		t.Fatal("IPv4 reassembly conversion drifted")
	}
	if ipv4MinReassemblyIP != 576 || ipv6MinIPPacket != 1280 {
		t.Fatal("RFC 9147 ICMP-ignore IP floors drifted")
	}
	if defaultPLPMTU != 1200 {
		t.Fatalf("default dtls-mtu %d", defaultPLPMTU)
	}
	if datagramOverhead(0, defaultAEADTag) != 22 {
		t.Fatalf("no-CID AES overhead %d want 22", datagramOverhead(0, defaultAEADTag))
	}
	if rrcProbeOverhead(8, defaultAEADTag) != 39 {
		t.Fatalf("CID-8 RRC probe minimum %d want 39", rrcProbeOverhead(8, defaultAEADTag))
	}
}

func TestProbeTimeoutMeetsRFC8899(t *testing.T) {
	if probeTimeout < minProbeTimeout {
		t.Fatalf("probe timeout %s below RFC 8899 minimum %s", probeTimeout, minProbeTimeout)
	}
	if probeTimeout <= 15*time.Second {
		t.Fatalf("probe timeout %s is not larger than 15s", probeTimeout)
	}
}

func TestRRCProbePaddingCIDOverhead(t *testing.T) {
	tag := defaultAEADTag
	for _, cidLen := range []int{0, 8, 32} {
		minSize := rrcProbeOverhead(cidLen, tag)
		for _, size := range []int{minSize, 256, 512, 1200} {
			if size < minSize {
				continue
			}
			pad, err := rrcProbePadding(size, cidLen, tag)
			if err != nil {
				t.Fatalf("cid=%d size=%d: %v", cidLen, size, err)
			}
			if minSize+pad != size {
				t.Fatalf("cid=%d size=%d pad=%d min=%d", cidLen, size, pad, minSize)
			}
		}
		if _, err := rrcProbePadding(minSize-1, cidLen, tag); err == nil {
			t.Fatalf("cid=%d accepted undersize probe", cidLen)
		}
	}
	if _, err := rrcProbePadding(1<<20, 0, tag); err == nil {
		t.Fatal("accepted a probe larger than the record limit")
	}
}
