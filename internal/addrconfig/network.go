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

func PortFromText(text string) PortTarget { return portTarget(text) }

func (t HostTarget) IsLiteral() bool { return t.Literal.IsValid() }

func (t HostTarget) Empty() bool { return !t.IsLiteral() && strings.TrimSpace(t.Name) == "" }

// IsIPv4Literal is true for IPv4 and IPv4-mapped literals. Selection only;
// the stored address is not unmapped.
func (t HostTarget) IsIPv4Literal() bool {
	return t.IsLiteral() && t.Literal.Unmap().Is4()
}

// IP is the typed literal, or nil when the host must be resolved.
func (t HostTarget) IP() net.IP {
	if !t.IsLiteral() {
		return nil
	}
	return t.Literal.AsSlice()
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
	TCPWrapDaemon string
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

	MQPriority    OptionalUint32
	MQFlush       OptionalBool
	MQMaxMessages OptionalInt
	MQMessageSize OptionalInt
}

func decodeNetwork(d *decoder, spec parse.Spec) error {
	a := &d.Address
	n := &a.Network
	n.Kind = a.Facts.Kind
	n.Role = a.Facts.Role
	n.IPFamily = a.Facts.Family
	n.TUNType = TUNTypeTUN

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
		if n.Role == AddressRoleListen {
			if len(a.Params) == 1 && a.Params[0] != "" {
				port, err := vsockUint32(a.Params[0])
				if err != nil {
					return fmt.Errorf("%s: port: %w", a.Type, err)
				}
				n.VSOCKListen, n.VSOCKListenSet = port, true
			}
		} else if len(a.Params) == 2 {
			cid, err := vsockUint32(a.Params[0])
			if err != nil {
				return fmt.Errorf("%s: cid: %w", a.Type, err)
			}
			if a.Params[0] == "" {
				cid = ^uint32(0)
			}
			port, err := vsockUint32(a.Params[1])
			if err != nil {
				return fmt.Errorf("%s: port: %w", a.Type, err)
			}
			n.VSOCKConnect, n.VSOCKConnectSet = VSOCKEndpoint{CID: cid, Port: port}, true
		}
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
	default:
		switch n.Role {
		case AddressRoleConnect, AddressRoleSendTo, AddressRoleDatagram:
			decodeHostPort(n, a.Params)
		case AddressRoleListen, AddressRoleReceive, AddressRoleReceiveFrom:
			if len(a.Params) >= 1 && a.Params[0] != "" {
				n.ListenPort = portTarget(a.Params[0])
				n.ListenSet = true
			}
		}
	}
	return nil
}

func decodeNetworkOption(a *Address, o parse.Option) (bool, error) {
	n := &a.Network
	name := optionIdentity(o)
	switch name {
	case "bind":
		text := optionText(o)
		if n.Kind == AddressKindSocket {
			data, err := ParseSocatData(text)
			if err != nil {
				return true, err
			}
			n.RawBind, n.RawBindSet = data, true
			return true, nil
		}
		if n.Kind == AddressKindVSOCK {
			ep, hasPort, err := decodeVSOCKBind(o.Value)
			if err != nil {
				return true, err
			}
			n.VSOCKBind, n.VSOCKBindSet, n.VSOCKBindHasPort = ep, true, hasPort
			n.BindSet = true
			return true, nil
		}
		n.Bind, n.BindPort, n.BindPortSet = parseBindValue(text, bindSplitsHostPort(n))
		n.BindSet = true
		return true, nil
	case "sourceport":
		text := optionText(o)
		n.SourcePort = portTarget(text)
		n.SourcePortSet = true
		return true, nil
	case "lowport":
		return true, setActive(&n.LowPort, o)
	case "range":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		parsed, err := ParseIPRange(value)
		if err != nil {
			return true, err
		}
		n.Range, n.RangeSet = parsed, true
		return true, nil
	case "tcpwrap":
		n.TCPWrap = activeBool(o)
		n.TCPWrapDaemon = ""
		if o.Has && o.Value != "" && o.Value != "1" {
			n.TCPWrapDaemon = o.Value
		}
		return true, nil
	case "tcpwrap-etc", "hosts-allow", "hosts-deny":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		opt := OptionalString{Set: true, Value: value}
		switch name {
		case "tcpwrap-etc":
			n.TCPWrapEtc = opt
		case "hosts-allow":
			n.HostsAllow = opt
		default:
			n.HostsDeny = opt
		}
		return true, nil
	case "pf":
		text := optionText(o)
		pf, known, err := protocolFamily(text)
		if err != nil {
			return true, err
		}
		if !known && (n.Kind == AddressKindSocket || n.Kind == AddressKindVSOCK) {
			return true, fmt.Errorf("unknown protocol family %q", text)
		}
		if known {
			n.ProtocolFamily, n.ProtocolSet, n.IPFamily = pf, true, ipFamilyOf(pf)
		}
		return true, nil
	case "socktype", "so-protocol":
		value, err := requiredSocketInt(o, name)
		if err != nil {
			return true, err
		}
		opt := OptionalInt{Set: true, Value: value}
		if name == "socktype" {
			n.SocketType = opt
		} else {
			n.SocketProtocol = opt
		}
		return true, nil
	case "protocol":
		if n.Kind != AddressKindSocket && n.Kind != AddressKindVSOCK {
			return false, nil
		}
		value, err := requiredSocketInt(o, "protocol")
		if err != nil {
			return true, err
		}
		n.SocketProtocol = OptionalInt{Set: true, Value: value}
		return true, nil
	case "reuseaddr":
		return true, setActive(&n.ReuseAddr, o)
	case "reuseport":
		return true, setActive(&n.ReusePort, o)
	case "ipv6-v6only":
		v, err := optionalBool(o)
		a.Common.IPv6V6Only = v
		return true, err
	case "unix-bind-tempname":
		n.UnixBindTempname = OptionalString{Set: true, Value: optionText(o)}
		return true, nil
	case "unix-tightsocklen":
		v, err := optionalBool(o)
		n.UnixTightSocklen = v
		return true, err
	case "backlog":
		backlog, err := decodePositiveInt(o)
		if err != nil {
			return true, fmt.Errorf("backlog: invalid value %q", o.Value)
		}
		n.Backlog = OptionalInt{Set: true, Value: backlog}
		return true, nil
	case "keepalive":
		return true, setActive(&n.KeepAlive, o)
	case "keepidle":
		return true, decodePositiveDuration(&n.KeepIdle, o)
	case "keepintvl":
		return true, decodePositiveDuration(&n.KeepIntvl, o)
	case "keepcnt":
		count, err := decodePositiveInt(o)
		if err != nil {
			return true, fmt.Errorf("keepcnt: invalid count %q", o.Value)
		}
		n.KeepCnt = OptionalInt{Set: true, Value: count}
		return true, nil
	case "nodelay":
		return true, setActive(&n.NoDelay, o)
	}
	if action, ok, err := socketAction(o, name); ok {
		if err != nil {
			return true, err
		}
		n.Actions = append(n.Actions, action)
		if action.Kind == SocketActionTimeout {
			opt := OptionalDuration{Set: true, Value: action.Duration}
			if action.Recv {
				a.Common.ReadTimeout = opt
			} else {
				a.Common.WriteTimeout = opt
			}
		}
		return true, nil
	}
	if handled, err := decodeTUNOption(n, o, name); handled {
		return true, err
	}
	if handled, err := decodePOSIXMQOption(n, o, name); handled {
		return true, err
	}
	return false, nil
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

func decodePROXYPositional(a *Address) error {
	p := a.Params
	var server, host, port string
	switch {
	case len(p) >= 3:
		server, host, port = p[0], p[1], p[2]
	case len(p) == 2:
		h, pt, err := net.SplitHostPort(p[1])
		if err == nil {
			server, host, port = p[0], h, pt
		}
	case len(p) == 1:
		parts := strings.Split(p[0], ":")
		if len(parts) >= 3 {
			server, host, port = parts[0], parts[1], parts[2]
		}
	}
	if server == "" || host == "" || port == "" {
		return fmt.Errorf("%s requires proxy, host, and port", a.Type)
	}
	a.Proxy.Server = targetFromText(server)
	a.Proxy.Target = targetFromText(host)
	a.Proxy.TargetPort = portTarget(port)
	a.Proxy.EndpointsSet = true
	return nil
}

func decodeSOCKSPositional(d *decoder) error {
	a := &d.Address
	p := a.Params
	var server, host, port, socksPort string
	switch {
	case len(p) >= 4:
		server, socksPort, host, port = p[0], p[1], p[2], p[3]
	case len(p) >= 3:
		server, host, port = p[0], p[1], p[2]
	case len(p) == 2:
		h, pt, err := net.SplitHostPort(p[1])
		if err == nil {
			server, host, port = p[0], h, pt
		}
	}
	if server == "" || host == "" || port == "" {
		return fmt.Errorf("%s requires socks-server, host, and port", a.Type)
	}
	a.Proxy.Server = targetFromText(server)
	a.Proxy.Target = targetFromText(host)
	a.Proxy.TargetPort = portTarget(port)
	a.Proxy.EndpointsSet = true
	if socksPort != "" {
		d.socksPositionalPort = portTarget(socksPort)
		d.socksPositionalPortSet = true
		a.Proxy.SOCKSPort = d.socksPositionalPort
		a.Proxy.SOCKSPortSet = true
	}
	return nil
}

func decodeWebSocketPositional(d *decoder) error {
	a := &d.Address
	n := &a.Network
	if n.Role == AddressRoleListen {
		if len(a.Params) < 1 || a.Params[0] == "" {
			return nil
		}
		port, path := splitPortPath(a.Params[0])
		n.ListenPort = portTarget(port)
		n.ListenSet = port != ""
		if path == "" && len(a.Params) > 1 {
			path = "/" + strings.Join(a.Params[1:], "/")
		}
		setWebSocketPositionalPath(d, path)
		return nil
	}
	if len(a.Params) >= 2 && a.Params[0] != "" && a.Params[1] != "" {
		n.Target = targetFromText(a.Params[0])
		port, path := splitPortPath(a.Params[1])
		n.TargetPort = portTarget(port)
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

func decodeHostPort(n *Network, params []string) {
	if len(params) >= 2 && params[0] != "" && params[1] != "" {
		n.Target = targetFromText(params[0])
		n.TargetPort = portTarget(params[1])
		n.TargetSet = true
		return
	}
	if len(params) != 1 || params[0] == "" {
		return
	}
	host, port, err := net.SplitHostPort(params[0])
	if err != nil || host == "" || port == "" {
		return
	}
	n.Target = targetFromText(host)
	n.TargetPort = portTarget(port)
	n.TargetSet = true
}

func targetFromText(text string) HostTarget {
	if ip, err := netip.ParseAddr(stripBrackets(text)); err == nil {
		return HostTarget{Literal: ip, Name: text}
	}
	return HostTarget{Name: text}
}

func bindSplitsHostPort(n *Network) bool {
	switch n.Kind {
	case AddressKindSocket, AddressKindVSOCK, AddressKindTUN, AddressKindINTERFACE, AddressKindFD, AddressKindPOSIXMQ, AddressKindRawIP:
		return false
	}
	switch n.Role {
	case AddressRoleConnect, AddressRoleSendTo, AddressRoleDatagram:
		return true
	default:
		return false
	}
}

func parseBindValue(text string, splitHostPort bool) (HostTarget, PortTarget, bool) {
	if splitHostPort {
		if h, p, err := net.SplitHostPort(text); err == nil && !bindHostLooksLikePath(h) {
			return targetFromText(h), portTarget(p), true
		}
	}
	return targetFromText(text), PortTarget{}, false
}

func bindHostLooksLikePath(host string) bool {
	return strings.ContainsAny(host, `/\`) || strings.HasPrefix(host, "@")
}

func portTarget(text string) PortTarget {
	p := PortTarget{Service: text}
	if n, err := strconv.ParseUint(text, 10, 16); err == nil {
		p.Number, p.Numeric = uint16(n), true
	}
	return p
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

func protocolFamily(value string) (int, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false, nil
	}
	if value[0] >= '0' && value[0] <= '9' {
		n, err := socketIntText(value)
		if err != nil {
			return 0, false, fmt.Errorf("unknown protocol family %q", value)
		}
		return n, true, nil
	}
	switch strings.ToLower(value) {
	case "inet", "inet4", "ip4", "ipv4":
		return socketFamilyIPv4, true, nil
	case "inet6", "ip6", "ipv6":
		return socketFamilyIPv6, true, nil
	default:
		return 0, false, nil
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

func socketAddressData(a *Address, spec parse.Spec, paramIndex int) ([]byte, error) {
	text := rawSocketAddress(a.Type, spec.Raw, paramIndex)
	if text == "" && paramIndex < len(a.Params) {
		text = strings.Join(a.Params[paramIndex:], ":")
	}
	if strings.Trim(text, ":") == "" {
		return nil, fmt.Errorf("%s requires address", a.Type)
	}
	return ParseSocatData(text)
}

func rawSocketAddress(typ, raw string, paramIndex int) string {
	up := strings.ToUpper(raw)
	prefix := typ + ":"
	if strings.HasPrefix(up, strings.ToUpper(prefix)) {
		raw = raw[len(prefix):]
	} else if i := strings.IndexByte(raw, ':'); i >= 0 {
		raw = raw[i+1:]
	}
	raw = cutTopLevelComma(raw)
	parts := splitColonNoUnquote(raw)
	if paramIndex >= len(parts) {
		return ""
	}
	return strings.Join(parts[paramIndex:], ":")
}

func cutTopLevelComma(value string) string {
	scanner := parse.NewSpecScanner(value, false)
	for {
		c, class, ok := scanner.Step()
		if !ok {
			return value
		}
		if class == parse.ClassTop && c == ',' {
			return value[:scanner.Pos()-1]
		}
	}
}

func splitColonNoUnquote(value string) []string {
	if value == "" {
		return nil
	}
	var values []string
	start := 0
	scanner := parse.NewSpecScanner(value, false)
	for {
		c, class, ok := scanner.Step()
		if !ok {
			break
		}
		if class == parse.ClassTop && c == ':' {
			values = append(values, value[start:scanner.Pos()-1])
			start = scanner.Pos()
		}
	}
	return append(values, value[start:])
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

func vsockUint32(value string) (uint32, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	n, err := ParseSizeT(value)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil // #nosec G115 -- VSOCK uses the C uint32_t conversion
}

func decodeVSOCKBind(value string) (VSOCKEndpoint, bool, error) {
	cidStr, portStr, hasPort := splitVSOCKBind(value)
	cid := ^uint32(0)
	if cidStr != "" {
		var err error
		cid, err = vsockUint32(cidStr)
		if err != nil {
			return VSOCKEndpoint{}, hasPort, fmt.Errorf("bind: cid: %w", err)
		}
	}
	ep := VSOCKEndpoint{CID: cid, Port: ^uint32(0)}
	if !hasPort {
		return ep, false, nil
	}
	port, err := vsockUint32(portStr)
	if err != nil {
		return VSOCKEndpoint{}, true, fmt.Errorf("bind: port: %w", err)
	}
	ep.Port = port
	return ep, true, nil
}

func splitVSOCKBind(bind string) (cidStr, portStr string, hasPort bool) {
	if i := strings.IndexByte(bind, ':'); i >= 0 {
		return bind[:i], bind[i+1:], true
	}
	return bind, "", false
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

func decodeTUNPositional(a *Address) error {
	n := 0
	for _, p := range a.Params {
		if p != "" {
			n++
		}
	}
	if n > 1 || len(a.Params) > 1 {
		return fmt.Errorf("too many parameters (%d instead of 0 or 1)", len(a.Params))
	}
	if len(a.Params) == 0 || a.Params[0] == "" {
		return nil
	}
	value := a.Params[0]
	if !strings.Contains(value, "/") {
		value += "/24"
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("TUN address %q: IPv4 required", a.Params[0])
	}
	a.Network.TUNAddress, a.Network.TUNAddressSet = prefix, true
	return nil
}

func decodeTUNOption(n *Network, o parse.Option, name string) (bool, error) {
	switch name {
	case "tun-device", "tun-name":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		if name == "tun-device" {
			n.TUNDevice = value
		} else {
			n.TUNName = value
		}
	case "tun-type":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		switch strings.ToLower(value) {
		case "tun":
			n.TUNType = TUNTypeTUN
		case "tap":
			n.TUNType = TUNTypeTAP
		default:
			return true, fmt.Errorf("unknown tun-type %q", value)
		}
	case "iff-no-pi":
		v, err := optionalBool(o)
		if err != nil {
			return true, err
		}
		n.TUNNoPacketInfo = v
	case "if-mtu":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		mtu, err := strconv.ParseUint(value, 0, 32)
		if err != nil || mtu == 0 {
			return true, fmt.Errorf("if-mtu: invalid %q", value)
		}
		n.TUNMTU = OptionalUint32{Set: true, Value: uint32(mtu)}
	case "retrieve-vlan":
		if o.Has {
			return true, fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
		n.TUNRetrieveVLAN = true
	default:
		bit, ok := interfaceFlagBit(name)
		if !ok {
			return false, nil
		}
		v, err := optionalBool(o)
		if err != nil {
			return true, err
		}
		if v.Value {
			n.TUNInterfaceSet |= bit
			n.TUNInterfaceClr &^= bit
		} else {
			n.TUNInterfaceClr |= bit
			n.TUNInterfaceSet &^= bit
		}
	}
	return true, nil
}

func interfaceFlagBit(name string) (uint16, bool) {
	flags := map[string]uint16{
		"iff-up":          0x1,
		"iff-broadcast":   0x2,
		"iff-debug":       0x4,
		"iff-loopback":    0x8,
		"iff-pointopoint": 0x10,
		"iff-notrailers":  0x20,
		"iff-running":     0x40,
		"iff-noarp":       0x80,
		"iff-promisc":     0x100,
		"iff-allmulti":    0x200,
		"iff-master":      0x400,
		"iff-slave":       0x800,
		"iff-multicast":   0x1000,
		"iff-portsel":     0x2000,
		"iff-automedia":   0x4000,
	}
	bit, ok := flags[name]
	return bit, ok
}

func decodePOSIXMQOption(n *Network, o parse.Option, name string) (bool, error) {
	switch name {
	case "mq-prio":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		v, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return true, fmt.Errorf("invalid mq-prio %q", value)
		}
		n.MQPriority = OptionalUint32{Set: true, Value: uint32(v)}
	case "mq-flush":
		return true, setActive(&n.MQFlush, o)
	case "mq-maxmsg":
		return true, setRequiredInt(&n.MQMaxMessages, o, 0)
	case "mq-msgsize":
		return true, setRequiredInt(&n.MQMessageSize, o, 0)
	default:
		return false, nil
	}
	return true, nil
}
