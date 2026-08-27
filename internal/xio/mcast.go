//go:build unix

package xio

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
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

	group, err := parseMcastGroup(fields[0], optionName)
	if err != nil {
		return parsedMcast{}, fmt.Errorf("%s: %w", optionName, err)
	}

	if len(fields) == 2 {
		token := strings.TrimSpace(fields[1])
		if token == "" {
			return parsedMcast{}, fmt.Errorf("%s: expected mcast:iface, got %q", optionName, spec)
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
	addr, err := resolveMcastIPv4Address(addrTok)
	if err != nil {
		return parsedMcast{}, fmt.Errorf("%s: bad interface address %q", optionName, addrTok)
	}
	return parsedMcast{group: group, ifaceAddr: addr, token: nameTok}, nil
}

func parseMcastGroup(field, optionName string) (net.IP, error) {
	field = strings.TrimSpace(field)
	if strings.HasPrefix(field, "[") {
		if !strings.HasSuffix(field, "]") {
			return nil, fmt.Errorf("bad group %q", field)
		}
		field = field[1 : len(field)-1]
	}
	if gip := net.ParseIP(field); gip != nil {
		return gip, nil
	}
	// Classic defers this field to xioresolve(), so hostnames are valid too.
	// For names, use the family selected by the distinct classic spelling.
	network := "ip4"
	if family, _, ok := membershipFamilyName(optionName); ok && family == membershipFamilyIPv6 {
		network = "ip6"
	} else if family, _, ok := sourceMembershipName(optionName); ok && family == membershipFamilyIPv6 {
		network = "ip6"
	}
	addr, err := net.ResolveIPAddr(network, field)
	if err != nil || addr == nil || addr.IP == nil {
		return nil, fmt.Errorf("bad group %q", field)
	}
	return addr.IP, nil
}

func resolveMcastIPv4Address(field string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip4", strings.TrimSpace(field))
	if err != nil || addr == nil || addr.IP.To4() == nil {
		return nil, fmt.Errorf("bad IPv4 address %q", field)
	}
	return addr.IP.To4(), nil
}

// splitMcastFields splits on ':' outside '[' ']' (classic nestlex nests).
// IPv6 groups therefore use the bracketed form, e.g. [ff02::2]:eth0.
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
	if err != nil && join.family == membershipFamilyIPv4 && !parsed.fieldsThree() {
		// Classic tries ifindex() first and then xioresolve() for the two-field
		// IPv4 form, so an address may also be supplied as a resolvable name.
		if addr, addrErr := resolveMcastIPv4Address(parsed.token); addrErr == nil {
			parsed.ifaceAddr = addr
			parsed.token = ""
			idx, idxSet, err = 0, false, nil
		}
	}
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

func applyMulticastNamedFD(fd int, kind multicastNamedKind, name string, o parse.Option) error {
	switch kind {
	case multicastNamedIf:
		if !o.Has || strings.TrimSpace(o.Value) == "" {
			return fmt.Errorf("%s: expected IPv4 hostname or address", name)
		}
		addr, err := resolveMcastIPv4Address(o.Value)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		var ip4 [4]byte
		copy(ip4[:], addr.To4())
		if err := setSockoptInet4Addr(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_IF, ip4); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	case multicastNamedLoop, multicastNamedTTL:
		n, err := classicFlagInt(o, 255)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		opt := unix.IP_MULTICAST_LOOP
		if kind == multicastNamedTTL {
			opt = unix.IP_MULTICAST_TTL
		}
		if err := setSockoptByte(fd, unix.IPPROTO_IP, opt, byte(n)); err != nil { // #nosec G115 -- classicFlagInt max 255
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	case multicastNamedIPv6Loop:
		family, err := socketIPFamily(fd)
		if err != nil {
			return err
		}
		if family == ipFamilyV4 {
			return fmt.Errorf("%s: not supported on IPv4", name)
		}
		n, err := classicFlagInt(o, -1)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := setSockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, n); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	default:
		return fmt.Errorf("%s: internal error", name)
	}
}

func (p parsedMcast) fieldsThree() bool {
	return p.ifaceAddr != nil && p.token != ""
}

// resolveMcastInterface implements classic ifindex() from sysutils.c:
// a fully-consumed base-0 C integer token is the numeric index (no existence
// lookup); otherwise if_nametoindex / InterfaceByName.
func resolveMcastInterface(p parsedMcast, optionName string) (uint32, bool, error) {
	if p.token == "" {
		return 0, false, nil
	}
	if idx, ok := parseClassicInterfaceIndex(p.token); ok {
		return idx, true, nil
	}
	ifi, err := net.InterfaceByName(p.token)
	if err != nil {
		return 0, false, fmt.Errorf("%s: interface %q: %w", optionName, p.token, err)
	}
	idx, ok := Uint32FromInt(ifi.Index)
	if !ok {
		return 0, false, fmt.Errorf("%s: interface %q index %d is out of range", optionName, p.token, ifi.Index)
	}
	return idx, true, nil
}

func parseClassicInterfaceIndex(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	// strconv's base-0 grammar additionally accepts Go's 0b/0o prefixes and
	// underscores; C strtol(..., 0), which classic uses, accepts none of them.
	unsigned := s
	if unsigned[0] == '+' || unsigned[0] == '-' {
		unsigned = unsigned[1:]
	}
	if unsigned == "" || strings.ContainsRune(unsigned, '_') ||
		strings.HasPrefix(unsigned, "0b") || strings.HasPrefix(unsigned, "0B") ||
		strings.HasPrefix(unsigned, "0o") || strings.HasPrefix(unsigned, "0O") {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 0, strconv.IntSize)
	if err != nil {
		return 0, false
	}
	// Classic assigns the signed long directly to unsigned int. Preserve that
	// conversion, including negative values and high-bit interface indices;
	// the kernel remains responsible for accepting or rejecting the result.
	return uint32(n), true // #nosec G115 -- deliberate classic strtol-to-unsigned-int conversion
}

func setIPv6MembershipFD(fd int, group net.IP, ifindex uint32) error {
	var mreq unix.IPv6Mreq
	copy(mreq.Multiaddr[:], group.To16())
	mreq.Interface = ifindex
	recordSockoptBytes(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, nil)
	if err := unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &mreq); err != nil {
		return fmt.Errorf("ipv6-join-group: %w", err)
	}
	return nil
}
