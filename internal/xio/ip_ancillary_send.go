package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
)

// maxIPOptions is the accumulated IP_OPTIONS byte cap (getsockopt buffer
// and append).
const maxIPOptions = 256

func ipSendAppliesToNetwork(network string) bool {
	n := strings.ToLower(network)
	if i := strings.IndexByte(n, ':'); i >= 0 {
		n = n[:i]
	}
	switch {
	case strings.HasPrefix(n, "tcp"), strings.HasPrefix(n, "udp"), strings.HasPrefix(n, "sctp"):
		return true
	case n == "ip", n == "ip4", n == "ip6":
		return true
	default:
		return false
	}
}

func applyPreparedAncillary(fd int, action addrconfig.SocketAction, family *ipFamily, familyResolved *bool) error {
	e, ok := lookupIPAncillary(action.Ancillary)
	if !ok {
		return nil
	}
	if familyResolved != nil && !*familyResolved {
		got, err := socketIPFamily(fd)
		if err != nil {
			return err
		}
		*family = got
		*familyResolved = true
	}
	resolved := ipFamilyUnknown
	if family != nil {
		resolved = *family
	}
	switch {
	case e.Kind&IPAncillarySend != 0:
		return applyPreparedIPSend(fd, e, action, resolved)
	case e.Kind&IPAncillaryRecv != 0:
		return applyPreparedIPRecv(fd, e, action.Number, resolved)
	default:
		return nil
	}
}

func applyPreparedIPSend(fd int, e IPAncillaryEntry, action addrconfig.SocketAction, family ipFamily) error {
	if err := rejectIPAncillaryApply(e, family); err != nil {
		return err
	}
	switch e.ID {
	case addrconfig.AncillaryIPOptions:
		if len(action.Value.Bytes) == 0 {
			return nil
		}
		if err := applyIPOptionsBytes(fd, append([]byte(nil), action.Value.Bytes...)); err != nil {
			return fmt.Errorf("ip-options: %w", err)
		}
		return nil
	case addrconfig.AncillaryIPHdrincl:
		if err := applyIPHdrincl(fd, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	case addrconfig.AncillaryIPTTL:
		if err := setSockoptInt(fd, ipLevelIP, ipOptTTL, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	case addrconfig.AncillaryIPTOS:
		if err := setSockoptInt(fd, ipLevelIP, ipOptTOS, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	case addrconfig.AncillaryIPv6UnicastHops:
		if err := setSockoptInt(fd, ipLevelIPv6, ipOptUnicastHops, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	case addrconfig.AncillaryIPv6Tclass:
		if err := applyIPv6Tclass(fd, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	default:
		return nil
	}
}
