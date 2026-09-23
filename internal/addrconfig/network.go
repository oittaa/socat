package addrconfig

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// AddressKind identifies the resource family selected by the address registry.
type AddressKind uint8

const (
	AddressKindOther AddressKind = iota
	AddressKindRawIP
	AddressKindUDP
	AddressKindSocket
	AddressKindVSOCK
	AddressKindTUN
	AddressKindINTERFACE
	AddressKindPOSIXMQ
	AddressKindFD
	AddressKindDTLS
	AddressKindWebSocket
	AddressKindPROXY
	AddressKindSOCKS
	AddressKindEXEC
	AddressKindSYSTEM
	AddressKindSHELL
	AddressKindUNIX
	AddressKindABSTRACT
	AddressKindFile
	AddressKindCREATE
	AddressKindPIPE
	AddressKindGOPEN
)

// IPFamily is the registry- or pf=-selected internet protocol family.
type IPFamily uint8

const (
	IPFamilyAny IPFamily = iota
	IPFamilyIPv4
	IPFamilyIPv6
	IPFamilyOther
)

// AddressRole identifies an address's connection lifetime.
type AddressRole uint8

const (
	AddressRoleOther AddressRole = iota
	AddressRoleConnect
	AddressRoleListen
	AddressRoleSendTo
	AddressRoleDatagram
	AddressRoleReceive
	AddressRoleReceiveFrom
)

// HostTarget is a literal IP or a name resolved at open time.
type HostTarget struct {
	Literal netip.Addr
	Name    string
}

func HostFromText(text string) HostTarget { return targetFromText(text) }

// PortFromText decodes a port token. An invalid numeric token is returned as
// a non-numeric service spelling so callers that only need a typed value can
// still inspect it; address decoding uses ParsePort and reports the error.
func PortFromText(text string) PortTarget {
	p, err := ParsePort(text)
	if err != nil {
		return PortTarget{Service: text}
	}
	return p
}

// ParsePort decodes a port once. A leading digit is a C strtoul value and must
// be an in-range uint16. Anything else is a service name, resolved later.
func ParsePort(text string) (PortTarget, error) { return portTarget(text) }

// PortNumber is a port already known as an integer. It does not parse text.
func PortNumber(n uint16) PortTarget {
	return PortTarget{Number: n, Numeric: true, Service: strconv.FormatUint(uint64(n), 10)}
}

func (t HostTarget) IsLiteral() bool { return t.Literal.IsValid() }

func (t HostTarget) Empty() bool { return !t.IsLiteral() && strings.TrimSpace(t.Name) == "" }

// IsIPv4Literal is true for IPv4 and IPv4-mapped literals. Selection only;
// the stored address is not unmapped.
func (t HostTarget) IsIPv4Literal() bool {
	return t.IsLiteral() && t.Literal.Unmap().Is4()
}

// IP is the typed literal, or nil when the host must be resolved.
// An IPv6 zone is not part of net.IP; use Zone.
func (t HostTarget) IP() net.IP {
	if !t.IsLiteral() {
		return nil
	}
	return t.Literal.AsSlice()
}

// Zone is the IPv6 scope of a literal address, or empty.
func (t HostTarget) Zone() string {
	if !t.IsLiteral() {
		return ""
	}
	return t.Literal.Zone()
}

// String returns the original address spelling without brackets.
func (t HostTarget) String() string {
	if t.IsLiteral() {
		return t.Literal.String()
	}
	return t.Name
}

// Original is the input spelling, including brackets on IPv6 literals.
func (t HostTarget) Original() string {
	if t.Name != "" {
		return t.Name
	}
	return t.String()
}

type PortTarget struct {
	Number  uint16
	Service string
	Numeric bool
}

// Text is the original port spelling. Numeric ports keep leading zeros.
func (p PortTarget) Text() string {
	if p.Service != "" {
		return p.Service
	}
	if p.Numeric {
		return strconv.FormatUint(uint64(p.Number), 10)
	}
	return ""
}

func (p PortTarget) Empty() bool {
	return !p.Numeric && p.Service == ""
}

func (p PortTarget) IsZero() bool {
	return p.Numeric && p.Number == 0
}

// ProtocolFamilyToken is a diagnostic spelling of pf=. Execution uses IPFamily.
func (n Network) ProtocolFamilyToken() string {
	if !n.ProtocolSet {
		return ""
	}
	switch n.IPFamily {
	case IPFamilyIPv4:
		return "ip4"
	case IPFamilyIPv6:
		return "ip6"
	default:
		return strconv.Itoa(n.ProtocolFamily)
	}
}

// SocketPhase is the lifecycle stage for a socket action.
type SocketPhase uint8

const (
	SocketPhasePrebind SocketPhase = iota + 1
	SocketPhasePastSocket
	SocketPhaseConnected
	SocketPhaseLate
)

// SocketActionKind selects the fully decoded socket operation.
type SocketActionKind uint8

const (
	SocketActionGeneric SocketActionKind = iota + 1
	SocketActionNamed
	SocketActionBroadcast
	SocketActionBuffer
	SocketActionBindToDevice
	SocketActionLinger
	SocketActionTimeout
	SocketActionAncillary
	SocketActionMulticast
	SocketActionFreebind
	SocketActionTransparent
	SocketActionMTUDiscovery
	SocketActionRecvErr
	SocketActionRouterAlert
	SocketActionGetOnly
)

// NamedSocket is the dispatch identity of a named socket option.
type NamedSocket uint8

const (
	NamedSocketNone NamedSocket = iota
	NamedSocketDebug
	NamedSocketDontRoute
	NamedSocketOOBInline
	NamedSocketRcvLowat
	NamedSocketSndLowat
	NamedSocketPriority
	NamedSocketPassCred
	NamedSocketNoCheck
	NamedSocketDetachFilter
	NamedSocketTCPCork
	NamedSocketTCPDeferAccept
	NamedSocketTCPLinger2
	NamedSocketTCPMaxSeg
	NamedSocketTCPQuickAck
	NamedSocketTCPSyncnt
	NamedSocketTCPWindowClamp
	NamedSocketNoPush
	NamedSocketNoOpt
	NamedSocketSCTPNodelay
	NamedSocketSCTPMaxSeg
	NamedSocketTCPMaxSegLate
	NamedSocketFIOSETOWN
	NamedSocketSIOCSPGRP
)

// AncillaryOption is the dispatch identity of an IP/ancillary socket option.
type AncillaryOption uint8

const (
	AncillaryNone AncillaryOption = iota
	AncillarySOTimestamp
	AncillaryIPPktinfo
	AncillaryIPRecvTTL
	AncillaryIPRecvTOS
	AncillaryIPRecvOpts
	AncillaryIPRetOpts
	AncillaryIPRecvDstAddr
	AncillaryIPRecvIf
	AncillaryIPv6RecvPktinfo
	AncillaryIPv6RecvHopLimit
	AncillaryIPv6RecvTclass
	AncillaryIPv6RecvDstOpts
	AncillaryIPv6RecvHopOpts
	AncillaryIPv6RecvRtHdr
	AncillaryIPv6RecvPathMTU
	AncillaryIPTTL
	AncillaryIPTOS
	AncillaryIPOptions
	AncillaryIPHdrincl
	AncillaryIPv6UnicastHops
	AncillaryIPv6Tclass
)

// IPGetOnly is a recognized get-only IPv4 name that is never applied as a setter.
type IPGetOnly uint8

const (
	IPGetOnlyNone IPGetOnly = iota
	IPGetOnlyMTU
	IPGetOnlyPktoptions
)

// MulticastKind selects a multicast socket request.
type MulticastKind uint8

const (
	MulticastJoinIPv4 MulticastKind = iota + 1
	MulticastJoinIPv6
	MulticastInterfaceIPv4
	MulticastLoopIPv4
	MulticastTTLIPv4
	MulticastLoopIPv6
	MulticastSourceIPv4
	MulticastSourceIPv6
)

// MulticastRequest is parsed once; names resolve at application time.
type MulticastRequest struct {
	Kind          MulticastKind
	Name          string
	Group         HostTarget
	InterfaceAddr HostTarget
	InterfaceName string
	InterfaceID   uint32
	InterfaceIsID bool
	ThreeField    bool
	Value         int
	Source        HostTarget
}

// SocketValue is a decoded generic setsockopt payload.
type SocketValue struct {
	IsInt bool
	Int   int
	Bytes []byte
}

// SocketAction stores one operation in command-line order.
type SocketAction struct {
	Kind      SocketActionKind
	Phase     SocketPhase
	Named     NamedSocket
	Ancillary AncillaryOption
	GetOnly   IPGetOnly
	Kernel    string
	Number    int
	Option    int
	Duration  time.Duration
	Text      string
	Recv      bool
	IPv6      bool
	Value     SocketValue
	Multicast MulticastRequest
}

// RawSocketCall is a decoded SOCKET positional call.
type RawSocketCall struct {
	Set      bool
	Domain   int
	Type     int
	Protocol int
	Address  []byte
}

// VSOCKEndpoint is a fully decoded VSOCK address.
type VSOCKEndpoint struct {
	CID  uint32
	Port uint32
}

// TUNType chooses the Linux TUN device mode.
type TUNType uint8

const (
	TUNTypeTUN TUNType = iota + 1
	TUNTypeTAP
)

// WithoutSourcePort clears source-port filtering for UDP DATAGRAM receive.
func (n Network) WithoutSourcePort() Network {
	n.SourcePort = PortTarget{}
	n.SourcePortSet = false
	return n
}

func (n Network) LocalPort() (PortTarget, bool) {
	if n.BindPortSet {
		return n.BindPort, true
	}
	if n.SourcePortSet {
		return n.SourcePort, true
	}
	return PortTarget{}, false
}

// Network contains the immutable network and socket configuration.
type Network struct {
	Kind AddressKind
	Role AddressRole

	Target      HostTarget
	TargetPort  PortTarget
	TargetSet   bool
	ListenPort  PortTarget
	ListenSet   bool
	Bind        HostTarget
	BindSet     bool
	BindPort    PortTarget
	BindPortSet bool

	ProtocolFamily   int
	IPFamily         IPFamily
	ProtocolSet      bool
	SocketType       OptionalInt
	SocketProtocol   OptionalInt
	ReuseAddr        OptionalBool
	ReusePort        OptionalBool
	UnixBindTempname OptionalString
	UnixTightSocklen OptionalBool
	SocketPath       string
	Backlog          OptionalInt
	KeepAlive        OptionalBool
	KeepIdle         OptionalDuration
	KeepIntvl        OptionalDuration
	KeepCnt          OptionalInt
	NoDelay          OptionalBool
	RawSocket        RawSocketCall
	RawBind          []byte
	RawBindSet       bool

	Range         IPRange
	RangeSet      bool
	SourcePort    PortTarget
	SourcePortSet bool
	LowPort       OptionalBool
	TCPWrap       OptionalBool
	// TCPWrapDaemon is tcpwrap[=<name>]. Omitted uses the program name.
	TCPWrapDaemon OptionalString
	TCPWrapEtc    OptionalString
	HostsAllow    OptionalString
	HostsDeny     OptionalString
	Actions       []SocketAction

	VSOCKConnect     VSOCKEndpoint
	VSOCKConnectSet  bool
	VSOCKListen      uint32
	VSOCKListenSet   bool
	VSOCKBind        VSOCKEndpoint
	VSOCKBindSet     bool
	VSOCKBindHasPort bool

	TUNAddress      netip.Prefix
	TUNAddressSet   bool
	TUNDevice       string
	TUNName         string
	TUNType         TUNType
	TUNNoPacketInfo OptionalBool
	TUNInterfaceSet uint16
	TUNInterfaceClr uint16
	TUNMTU          OptionalUint32
	TUNRetrieveVLAN bool

	InterfaceName string

	MQName        string
	MQPriority    OptionalUint32
	MQFlush       OptionalBool
	MQMaxMessages OptionalInt
	MQMessageSize OptionalInt
}

func firstParam(params []string) string {
	if len(params) == 0 {
		return ""
	}
	return params[0]
}

func decodeNetwork(d *decoder, spec parse.Spec) error {
	a := &d.Address
	n := &a.Network
	n.Kind = a.Facts.Kind
	n.Role = a.Facts.Role
	// pf= may already have selected a family during option decoding.
	if !n.ProtocolSet {
		n.IPFamily = a.Facts.Family
	}
	if n.TUNType == 0 {
		n.TUNType = TUNTypeTUN
	}

	switch n.Kind {
	case AddressKindFD:
		return decodeFDPositional(a)
	case AddressKindRawIP:
		if n.Role == AddressRoleReceive || n.Role == AddressRoleReceiveFrom {
			if len(a.Params) >= 1 && a.Params[0] != "" {
				proto, err := socketIntText(a.Params[0])
				if err != nil || proto < 0 || proto > 255 {
					return fmt.Errorf("%s: bad protocol %q", a.Type, a.Params[0])
				}
				n.SocketProtocol = OptionalInt{Set: true, Value: proto}
			}
		} else if len(a.Params) >= 2 && a.Params[0] != "" && a.Params[1] != "" {
			proto, err := socketIntText(a.Params[1])
			if err != nil || proto < 0 || proto > 255 {
				return fmt.Errorf("%s: bad protocol %q", a.Type, a.Params[1])
			}
			n.Target = targetFromText(a.Params[0])
			n.TargetSet = true
			n.SocketProtocol = OptionalInt{Set: true, Value: proto}
		}
	case AddressKindVSOCK:
		return decodeVSOCKPositional(n, a.Type, a.Params)
	case AddressKindSocket:
		if err := decodeRawSocketCall(a, spec); err != nil {
			return err
		}
	case AddressKindTUN:
		if err := decodeTUNPositional(a); err != nil {
			return err
		}
	case AddressKindINTERFACE:
		return decodeINTERFACEPositional(a)
	case AddressKindWebSocket:
		return decodeWebSocketPositional(d)
	case AddressKindPROXY:
		return decodePROXYPositional(a)
	case AddressKindSOCKS:
		return decodeSOCKSPositional(d)
	case AddressKindEXEC, AddressKindSYSTEM, AddressKindSHELL:
		return nil
	case AddressKindFile, AddressKindCREATE, AddressKindPIPE, AddressKindGOPEN:
		a.File.Path = firstParam(a.Params)
		return nil
	case AddressKindUNIX, AddressKindABSTRACT:
		n.SocketPath = firstParam(a.Params)
		return nil
	case AddressKindPOSIXMQ:
		return decodePOSIXMQPositional(n, a.Params)
	default:
		switch n.Role {
		case AddressRoleConnect, AddressRoleSendTo, AddressRoleDatagram:
			return decodeHostPort(n, a.Params)
		case AddressRoleListen, AddressRoleReceive, AddressRoleReceiveFrom:
			if len(a.Params) >= 1 && a.Params[0] != "" {
				port, err := portTarget(a.Params[0])
				if err != nil {
					return err
				}
				n.ListenPort = port
				n.ListenSet = true
			}
		}
	}
	return nil
}

func ipFamilyOf(pf int) IPFamily {
	switch pf {
	case socketFamilyIPv4:
		return IPFamilyIPv4
	case socketFamilyIPv6:
		return IPFamilyIPv6
	default:
		return IPFamilyOther
	}
}

func decodeFDPositional(a *Address) error {
	if len(a.Params) != 1 || a.Params[0] == "" {
		return fmt.Errorf("wrong number of parameters (%d instead of 1)", len(a.Params))
	}
	n, err := strconv.ParseUint(a.Params[0], 0, 32)
	if err != nil {
		return fmt.Errorf("error in FD number %q", a.Params[0])
	}
	a.File.FD, a.File.FDSet = int(n), true
	return nil
}

func decodeINTERFACEPositional(a *Address) error {
	if len(a.Params) != 1 || a.Params[0] == "" {
		return fmt.Errorf("INTERFACE requires interface name")
	}
	a.Network.InterfaceName = a.Params[0]
	return nil
}

func decodeWebSocketPositional(d *decoder) error {
	a := &d.Address
	n := &a.Network
	if n.Role == AddressRoleListen {
		if len(a.Params) < 1 || a.Params[0] == "" {
			return nil
		}
		portText, path := splitPortPath(a.Params[0])
		port, err := portTarget(portText)
		if err != nil {
			return err
		}
		n.ListenPort = port
		n.ListenSet = portText != ""
		if path == "" && len(a.Params) > 1 {
			path = "/" + strings.Join(a.Params[1:], "/")
		}
		setWebSocketPositionalPath(d, path)
		return nil
	}
	if len(a.Params) >= 2 && a.Params[0] != "" && a.Params[1] != "" {
		n.Target = targetFromText(a.Params[0])
		portText, path := splitPortPath(a.Params[1])
		port, err := portTarget(portText)
		if err != nil {
			return err
		}
		n.TargetPort = port
		n.TargetSet = true
		if path == "" && len(a.Params) > 2 {
			path = "/" + strings.Join(a.Params[2:], "/")
		}
		setWebSocketPositionalPath(d, path)
	}
	return nil
}

func setWebSocketPositionalPath(d *decoder, path string) {
	if path == "" {
		return
	}
	d.wsPositionalPath = normalizeWSPath(path)
	if !d.TLS.WSPath.Set {
		d.TLS.WSPath = OptionalString{Set: true, Value: d.wsPositionalPath}
	}
}

func splitPortPath(value string) (port, path string) {
	i := strings.Index(value, "/")
	if i < 0 {
		return value, ""
	}
	return value[:i], value[i:]
}

func normalizeWSPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func decodeHostPort(n *Network, params []string) error {
	if len(params) >= 2 && params[0] != "" && params[1] != "" {
		port, err := portTarget(params[1])
		if err != nil {
			return err
		}
		n.Target = targetFromText(params[0])
		n.TargetPort = port
		n.TargetSet = true
		return nil
	}
	if len(params) != 1 || params[0] == "" {
		return nil
	}
	host, portText, err := net.SplitHostPort(params[0])
	if err != nil || host == "" || portText == "" {
		return nil
	}
	port, err := portTarget(portText)
	if err != nil {
		return err
	}
	n.Target = targetFromText(host)
	n.TargetPort = port
	n.TargetSet = true
	return nil
}

func targetFromText(text string) HostTarget {
	if ip, err := netip.ParseAddr(stripBrackets(text)); err == nil {
		return HostTarget{Literal: ip, Name: text}
	}
	return HostTarget{Name: text}
}

func filesystemBindKind(kind AddressKind) bool {
	return kind == AddressKindUNIX || kind == AddressKindGOPEN
}

func bindSplitsHostPort(n *Network) bool {
	switch n.Kind {
	case AddressKindSocket, AddressKindVSOCK, AddressKindTUN, AddressKindINTERFACE, AddressKindFD, AddressKindPOSIXMQ, AddressKindRawIP, AddressKindUNIX, AddressKindABSTRACT:
		return false
	}
	switch n.Role {
	case AddressRoleConnect, AddressRoleSendTo, AddressRoleDatagram:
		return true
	default:
		return false
	}
}

func parseBindValue(text string, splitHostPort bool) (HostTarget, PortTarget, bool, error) {
	if splitHostPort {
		if h, p, err := net.SplitHostPort(text); err == nil && !bindHostLooksLikePath(h) {
			port, err := portTarget(p)
			if err != nil {
				return HostTarget{}, PortTarget{}, false, err
			}
			return targetFromText(h), port, true, nil
		}
	}
	return targetFromText(text), PortTarget{}, false, nil
}

func bindHostLooksLikePath(host string) bool {
	return strings.ContainsAny(host, `/\`) || strings.HasPrefix(host, "@")
}

func requiredPortTarget(o parse.Option) (PortTarget, error) {
	text, err := requiredString(o)
	if err != nil {
		return PortTarget{}, err
	}
	return portTarget(text)
}

func portTarget(text string) (PortTarget, error) {
	if text == "" {
		return PortTarget{}, nil
	}
	n, numeric, err := parseDigitStrtoul(text, 16)
	if err != nil {
		return PortTarget{}, fmt.Errorf("invalid port %q", text)
	}
	if !numeric {
		return PortTarget{Service: text}, nil
	}
	return PortTarget{Number: uint16(n), Service: text, Numeric: true}, nil // #nosec G115 -- parseDigitStrtoul bitSize 16 bounds the value
}

func stripBrackets(value string) string {
	if len(value) >= 2 && value[0] == '[' && value[len(value)-1] == ']' {
		return value[1 : len(value)-1]
	}
	return value
}

func socketIntText(value string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 0, 64)
	if err != nil || n > math.MaxInt || n < math.MinInt {
		return 0, fmt.Errorf("invalid")
	}
	return int(n), nil
}

func socketIntOrZero(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	return socketIntText(value)
}

func requiredSocketInt(o parse.Option, name string) (int, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, fmt.Errorf("option %q requires a number", name)
	}
	n, err := socketIntText(o.Value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s=%q", name, o.Value)
	}
	return n, nil
}

func protocolFamily(value string) (int, IPFamily, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, IPFamilyOther, fmt.Errorf("unknown protocol family %q", value)
	}
	if value[0] >= '0' && value[0] <= '9' {
		n, _, err := parseDigitStrtoul(value, strconv.IntSize)
		if err != nil || n > uint64(math.MaxInt) {
			return 0, IPFamilyOther, fmt.Errorf("unknown protocol family %q", value)
		}
		pf := int(n)
		return pf, ipFamilyOf(pf), nil
	}
	switch strings.ToLower(value) {
	case "inet", "inet4", "ip4", "ipv4":
		return socketFamilyIPv4, IPFamilyIPv4, nil
	case "inet6", "ip6", "ipv6":
		return socketFamilyIPv6, IPFamilyIPv6, nil
	default:
		return 0, IPFamilyOther, fmt.Errorf("unknown protocol family %q", value)
	}
}

func decodeRawSocketCall(a *Address, spec parse.Spec) error {
	n := &a.Network
	if n.Role == AddressRoleConnect || n.Role == AddressRoleListen {
		if len(a.Params) < 3 {
			return nil
		}
		domain, err := socketIntOrZero(a.Params[0])
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}
		proto, err := socketIntOrZero(a.Params[1])
		if err != nil {
			return fmt.Errorf("protocol: %w", err)
		}
		data, err := socketAddressData(a, spec, 2)
		if err != nil {
			return err
		}
		n.RawSocket = RawSocketCall{Set: true, Domain: domain, Type: 1, Protocol: proto, Address: data}
		return nil
	}
	if len(a.Params) < 4 {
		return nil
	}
	domain, err := socketIntOrZero(a.Params[0])
	if err != nil {
		return fmt.Errorf("domain: %w", err)
	}
	typ := 2
	if a.Params[1] != "" {
		typ, err = socketIntText(a.Params[1])
		if err != nil {
			return fmt.Errorf("type: %w", err)
		}
	}
	proto, err := socketIntOrZero(a.Params[2])
	if err != nil {
		return fmt.Errorf("protocol: %w", err)
	}
	data, err := socketAddressData(a, spec, 3)
	if err != nil {
		return err
	}
	n.RawSocket = RawSocketCall{Set: true, Domain: domain, Type: typ, Protocol: proto, Address: data}
	return nil
}

func socketAddressData(a *Address, _ parse.Spec, paramIndex int) ([]byte, error) {
	if paramIndex >= len(a.Params) {
		return nil, fmt.Errorf("%s requires address", a.Type)
	}
	text := strings.Join(a.Params[paramIndex:], ":")
	if strings.Trim(text, ":") == "" {
		return nil, fmt.Errorf("%s requires address", a.Type)
	}
	return ParseSocatData(text)
}

// ParseSocatData parses SOCKET address data.
func ParseSocatData(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if strings.HasPrefix(value, `\"`) {
		value = unescapeShellQuotes(value)
	}
	if value[0] == '\'' {
		if len(value) < 3 || value[len(value)-1] != '\'' {
			return nil, fmt.Errorf("syntax error in %q", value)
		}
		inner := value[1 : len(value)-1]
		if len(inner) == 1 {
			return []byte{inner[0]}, nil
		}
		if len(inner) == 2 && inner[0] == '\\' {
			return []byte{socketEscapeByte(inner[1])}, nil
		}
		return nil, fmt.Errorf("syntax error in %q", value)
	}
	if value[0] == '"' {
		out, rest, err := parseSocketString(value)
		if err != nil {
			return nil, err
		}
		if rest == "" {
			return out, nil
		}
		more, err := ParseSocatData(rest)
		if err != nil {
			return nil, err
		}
		return append(out, more...), nil
	}
	if value[0] == 'x' {
		var out []byte
		for _, part := range strings.Split(value, "x") {
			if part == "" {
				continue
			}
			if len(part)%2 != 0 {
				return nil, fmt.Errorf("syntax error in %q", value)
			}
			bytes, err := hex.DecodeString(part)
			if err != nil {
				return nil, fmt.Errorf("syntax error in %q", value)
			}
			out = append(out, bytes...)
		}
		return out, nil
	}
	if value[0] == 'X' {
		return nil, fmt.Errorf("syntax error in %q", value)
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
			out.WriteByte(socketEscapeByte(value[i]))
			continue
		}
		out.WriteByte(value[i])
	}
	return []byte(out.String()), nil
}

func unescapeShellQuotes(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) && (value[i+1] == '"' || value[i+1] == '\\') {
			out.WriteByte(value[i+1])
			i++
			continue
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

func parseSocketString(value string) ([]byte, string, error) {
	var out []byte
	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '"':
			return out, value[i+1:], nil
		case '\\':
			i++
			if i >= len(value) {
				return nil, "", fmt.Errorf("syntax error in %q", value)
			}
			out = append(out, socketEscapeByte(value[i]))
		default:
			out = append(out, value[i])
		}
	}
	return nil, "", fmt.Errorf("syntax error in %q", value)
}

func socketEscapeByte(value byte) byte {
	switch value {
	case '0':
		return 0
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'f':
		return '\f'
	case 'b':
		return '\b'
	case 'a':
		return '\a'
	case 'e':
		return 033
	default:
		return value
	}
}

func decodePositiveInt(o parse.Option) (int, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, fmt.Errorf("invalid")
	}
	n, err := socketIntText(o.Value)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid")
	}
	return n, nil
}

func positiveKeepDuration(o parse.Option) (time.Duration, error) {
	d, err := parseDurationValue(o)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", o.Name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: must be positive, got %q", o.Name, o.Value)
	}
	return d, nil
}
