package xio

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// Linux IPPROTO_RAW. IP4-SENDTO:host:255 uses this protocol;
// IP_ROUTER_ALERT returns EINVAL there (not a silent no-op).
const ipprotoRaw = 255

func getOnlyIPOptionName(o parse.Option) (canon, kernel, spelling string, ok bool) {
	if canon, kernel, ok = getOnlyIPSpelling(o.OriginalSpelling()); ok {
		return canon, kernel, optionSpelling(o), true
	}
	if canon, kernel, ok = getOnlyIPSpelling(o.Name); ok {
		return canon, kernel, optionSpelling(o), true
	}
	return "", "", "", false
}

func getOnlyIPSpelling(name string) (canon, kernel string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-mtu", "ipmtu", "mtu":
		return "ip-mtu", "IP_MTU", true
	case "ip-pktoptions", "ippktoptions", "pktoptions", "pktopts":
		return "ip-pktoptions", "IP_PKTOPTIONS", true
	default:
		return "", "", false
	}
}

func optionSpelling(o parse.Option) string {
	if s := o.OriginalSpelling(); s != "" {
		return s
	}
	return o.Name
}

func isRouterAlertOption(o parse.Option) bool {
	return routerAlertOptionName(o.OriginalSpelling()) || routerAlertOptionName(o.Name)
}

func routerAlertOptionName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ip-router-alert", "iprouteralert", "routeralert":
		return true
	default:
		return false
	}
}

// GetOnlyIPv4OptionNames are ip-mtu / ip-pktoptions spellings.
// They are recognized so validation can reject them as get-only instead of
// "unknown option". They are never advertised.
func GetOnlyIPv4OptionNames() []string {
	return []string{
		"ip-mtu", "ipmtu", "mtu",
		"ip-pktoptions", "ippktoptions", "pktoptions", "pktopts",
	}
}

func applyGetOnlyIPOption(_ int, o parse.Option) (bool, error) {
	_, kernel, spelling, ok := getOnlyIPOptionName(o)
	if !ok {
		return false, nil
	}
	return true, fmt.Errorf("%s: %s is get-only; not implemented as a setter", spelling, kernel)
}

func applyRouterAlertOption(fd int, o parse.Option) (bool, error) {
	if !isRouterAlertOption(o) {
		return false, nil
	}
	return true, applyRouterAlertFD(fd, o)
}

func rejectRouterAlert(s parse.Spec, o parse.Option) error {
	spelling := optionSpelling(o)
	if !isRawIPAddress(s.Type) {
		typ := s.Type
		if typ == "" {
			return fmt.Errorf("%s: not supported with this address type", spelling)
		}
		return fmt.Errorf("%s: option %q not supported with this address type", typ, spelling)
	}
	family := specForcedIPFamily(s)
	if family == ipFamilyV6 {
		return fmt.Errorf("%s: option %q not supported on IPv6", s.Type, spelling)
	}
	if proto, ok := specRawIPProtocolNumber(s); ok && proto == ipprotoRaw {
		return fmt.Errorf("%s: option %q is not supported on IPPROTO_RAW sockets", s.Type, spelling)
	}
	return nil
}

func isRawIPAddress(typ string) bool {
	if reg, ok := AddressRegistrationForType(typ); ok {
		return reg.Group == GroupRawIP
	}
	u := strings.ToUpper(strings.TrimSpace(typ))
	switch u {
	case "IP", "IP4", "IP6":
		return true
	}
	return strings.HasPrefix(u, "IP-") || strings.HasPrefix(u, "IP4-") || strings.HasPrefix(u, "IP6-")
}

func specRawIPProtocolNumber(s parse.Spec) (int, bool) {
	u := strings.ToUpper(strings.TrimSpace(s.Type))
	if !strings.HasPrefix(u, "IP") {
		return 0, false
	}
	idx := 1
	if strings.Contains(u, "RECV") {
		idx = 0
	}
	if len(s.Params) <= idx || s.Params[idx] == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s.Params[idx], 0, 8)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// RejectUnsupportedRemainingIPv4 fails fast for get-only ip-mtu /
// ip-pktoptions and for ip-router-alert combinations that are not
// implemented (IPv6, non-raw addresses, IPPROTO_RAW). Linux IP_MTU and
// IP_PKTOPTIONS are get-only; they are not advertised as setters.
func RejectUnsupportedRemainingIPv4(s parse.Spec) error {
	for _, o := range s.Options {
		if _, kernel, spelling, ok := getOnlyIPOptionName(o); ok {
			typ := s.Type
			if typ == "" {
				return fmt.Errorf("%s: %s is get-only; not implemented as a setter", spelling, kernel)
			}
			return fmt.Errorf("%s: option %q is get-only; %s is not implemented as a setter", typ, spelling, kernel)
		}
		if isRouterAlertOption(o) {
			if err := rejectRouterAlert(s, o); err != nil {
				return err
			}
		}
	}
	return nil
}
