//go:build unix

package xio

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// parsedMcast is one classic TYPE_IP_MREQN value.
//
// Documented IPv4 forms (doc/socat.yo OPTION_IP_ADD_MEMBERSHIP, tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is unchanged):
//
//	group:iface-address
//	group:iface-name
//	group:iface-index
//	group:iface-address:iface-name
//	group:iface-address:iface-index
//
// IPv6 (OPTION_IPV6_JOIN_GROUP) is two fields: group plus name or index.
// Classic's C parser for the three-field name form SIGSEGVs on some hosts
// (upstream bug); this port implements the documented interface safely.
type parsedMcast struct {
	group     net.IP
	ifaceAddr net.IP // optional IPv4 interface address (imr_address)
	token     string // remaining name or index; empty when only ifaceAddr
}

// parseMcastSpec parses classic ip-add-membership / ipv6-join-group.
func parseMcastSpec(spec, optionName string) (parsedMcast, error) {
	if optionName == "" {
		optionName = "ip-add-membership"
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return parsedMcast{}, fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
	}

	fields, err := splitMcastFields(spec)
	if err != nil {
		return parsedMcast{}, fmt.Errorf("%s: %w", optionName, err)
	}
	if len(fields) < 2 {
		return parsedMcast{}, fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
	}
	if len(fields) > 3 {
		return parsedMcast{}, fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
	}

	group, err := parseMcastGroup(fields[0])
	if err != nil {
		return parsedMcast{}, fmt.Errorf("%s: %w", optionName, err)
	}

	if len(fields) == 2 {
		token := strings.TrimSpace(fields[1])
		if token == "" {
			return parsedMcast{}, fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
		}
		if ip := net.ParseIP(token); ip != nil && ip.To4() != nil {
			return parsedMcast{group: group, ifaceAddr: ip.To4()}, nil
		}
		return parsedMcast{group: group, token: token}, nil
	}

	// Three-field IPv4 form. Classic xiotype_ip_add_membership stores
	// field 2 as interface address and field 3 as name/index (HAVE_STRUCT_IP_MREQN).
	addrTok := strings.TrimSpace(fields[1])
	nameTok := strings.TrimSpace(fields[2])
	if addrTok == "" || nameTok == "" {
		return parsedMcast{}, fmt.Errorf("%s: expected mcast:iface-address:iface, got %q", optionName, spec)
	}
	addr := net.ParseIP(addrTok)
	if addr == nil || addr.To4() == nil {
		return parsedMcast{}, fmt.Errorf("%s: bad interface address %q", optionName, addrTok)
	}
	return parsedMcast{group: group, ifaceAddr: addr.To4(), token: nameTok}, nil
}

func parseMcastGroup(field string) (net.IP, error) {
	field = strings.TrimSpace(field)
	if strings.HasPrefix(field, "[") {
		if !strings.HasSuffix(field, "]") {
			return nil, fmt.Errorf("bad group %q", field)
		}
		field = field[1 : len(field)-1]
	}
	gip := net.ParseIP(field)
	if gip == nil {
		return nil, fmt.Errorf("bad group %q", field)
	}
	return gip, nil
}

// splitMcastFields splits on ':' outside '[' ']' (classic nestlex nests).
// Unbracketed IPv6 with a trailing :iface uses the last colon.
func splitMcastFields(spec string) ([]string, error) {
	if i := strings.IndexByte(spec, '%'); i > 0 && !strings.Contains(spec, ":") {
		return []string{spec[:i], spec[i+1:]}, nil
	}
	var fields []string
	var b strings.Builder
	depth := 0
	for i := 0; i < len(spec); i++ {
		c := spec[i]
		switch c {
		case '[':
			depth++
			b.WriteByte(c)
		case ']':
			if depth > 0 {
				depth--
			}
			b.WriteByte(c)
		case ':':
			if depth == 0 {
				fields = append(fields, b.String())
				b.Reset()
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	fields = append(fields, b.String())
	if len(fields) >= 2 {
		return fields, nil
	}
	// Unbracketed IPv6: last colon separates iface.
	if i := strings.LastIndex(spec, ":"); i > 0 {
		if g := net.ParseIP(spec[:i]); g != nil {
			return []string{spec[:i], spec[i+1:]}, nil
		}
	}
	return nil, fmt.Errorf("expected mcast:iface, got %q", spec)
}

func applyMembershipJoins(fd int, joins []membershipJoin) error {
	for _, join := range joins {
		if err := joinMulticastFD(fd, join); err != nil {
			return err
		}
	}
	return nil
}

func joinMulticastFD(fd int, join membershipJoin) error {
	name := join.optionName()
	parsed, err := parseMcastSpec(join.spec, name)
	if err != nil {
		return err
	}
	if join.family == membershipFamilyIPv4 && parsed.group.To4() == nil {
		return fmt.Errorf("%s: IPv4 membership requires an IPv4 group, got %s", name, parsed.group)
	}
	if join.family == membershipFamilyIPv6 && parsed.fieldsThree() {
		return fmt.Errorf("%s: three-field form is IPv4-only", name)
	}
	if join.family == membershipFamilyIPv6 && parsed.ifaceAddr != nil && parsed.token == "" {
		return fmt.Errorf("%s: IPv6 membership requires an interface name or index, got address %s", name, parsed.ifaceAddr)
	}

	idx, idxSet, err := resolveMcastInterface(parsed, name)
	if err != nil {
		return err
	}
	if join.family == membershipFamilyIPv4 {
		return setIPv4MembershipFD(fd, parsed.group.To4(), parsed.ifaceAddr, idx, idxSet)
	}
	if !idxSet {
		return fmt.Errorf("%s: expected interface name or index", name)
	}
	return setIPv6MembershipFD(fd, parsed.group, idx)
}

func (p parsedMcast) fieldsThree() bool {
	return p.ifaceAddr != nil && p.token != ""
}

// resolveMcastInterface implements classic ifindex() from sysutils.c:
// a fully-consumed decimal token is the numeric index (no existence
// lookup); otherwise if_nametoindex / InterfaceByName.
func resolveMcastInterface(p parsedMcast, optionName string) (int, bool, error) {
	if p.token == "" {
		return 0, false, nil
	}
	if idx, ok := parseDecimalIndex(p.token); ok {
		return idx, true, nil
	}
	ifi, err := net.InterfaceByName(p.token)
	if err != nil {
		return 0, false, fmt.Errorf("%s: interface %q: %w", optionName, p.token, err)
	}
	return ifi.Index, true, nil
}

func parseDecimalIndex(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

func setIPv4MembershipFD(fd int, group, ifaceAddr net.IP, ifindex int, idxSet bool) error {
	// Linux IPv4 uses ip_mreqn so a name/index is imr_ifindex, not the
	// interface's first IPv4 address (classic xioapply_ip_add_membership
	// with HAVE_STRUCT_IP_MREQN).
	var mreqn unix.IPMreqn
	copy(mreqn.Multiaddr[:], group.To4())
	if ifaceAddr != nil {
		copy(mreqn.Address[:], ifaceAddr.To4())
	}
	if idxSet {
		idx32, err := int32FromInt(ifindex)
		if err != nil {
			return fmt.Errorf("ip-add-membership: %w", err)
		}
		mreqn.Ifindex = idx32
	}
	if err := unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreqn); err != nil {
		return fmt.Errorf("ip-add-membership: %w", err)
	}
	return nil
}

func setIPv6MembershipFD(fd int, group net.IP, ifindex int) error {
	ifi32, ok := Uint32FromInt(ifindex)
	if !ok {
		return fmt.Errorf("ipv6-join-group: interface index %d out of range", ifindex)
	}
	var mreq unix.IPv6Mreq
	copy(mreq.Multiaddr[:], group.To16())
	mreq.Interface = ifi32
	if err := unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &mreq); err != nil {
		return fmt.Errorf("ipv6-join-group: %w", err)
	}
	return nil
}

func int32FromInt(n int) (int32, error) {
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0, fmt.Errorf("interface index %d out of range", n)
	}
	return int32(n), nil
}
