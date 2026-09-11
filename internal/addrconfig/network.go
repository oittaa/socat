package addrconfig

import (
	"encoding/hex"
	"fmt"
	"math"
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
	AddressKindTCP
	AddressKindUDP
	AddressKindRawIP
	AddressKindSocket
	AddressKindSCTP
	AddressKindVSOCK
	AddressKindTUN
	AddressKindPOSIXMQ
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

// AddressFamily preserves a selected IP family without relying on a keyword
// prefix while a resource is opening.
type AddressFamily uint8

const (
	AddressFamilyAny AddressFamily = iota
	AddressFamilyIPv4
	AddressFamilyIPv6
)

// HostTarget distinguishes a literal IP address from a name that must be
// resolved during its resource attempt.
type HostTarget struct {
	Literal netip.Addr
	Name    string
}

// IsLiteral reports whether the target was an IP literal.
func (t HostTarget) IsLiteral() bool { return t.Literal.IsValid() }

// String returns the original address spelling without brackets.
func (t HostTarget) String() string {
	if t.IsLiteral() {
		return t.Literal.String()
	}
	return t.Name
}

// PortTarget distinguishes a numeric port from a service name lookup.
type PortTarget struct {
	Number  uint16
	Service string
	Numeric bool
}

// Text is the numeric port or service name. Zero numeric ports stay "0".
func (p PortTarget) Text() string {
	if p.Numeric {
		return strconv.FormatUint(uint64(p.Number), 10)
	}
	return p.Service
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
	SocketActionSourceMulticast
	SocketActionFreebind
	SocketActionTransparent
	SocketActionMTUDiscovery
	SocketActionRecvErr
)

// NamedSocketOption is a closed list of named integer socket options.
type NamedSocketOption uint8

const (
	NamedSocketDebug NamedSocketOption = iota + 1
	NamedSocketDontRoute
	NamedSocketOOBInline
	NamedSocketRecvLowWater
	NamedSocketSendLowWater
	NamedSocketPriority
	NamedSocketPassCred
	NamedSocketNoCheck
	NamedSocketDetachFilter
	NamedSocketTCPCork
	NamedSocketTCPDeferAccept
	NamedSocketTCPLinger2
	NamedSocketTCPMaxSeg
	NamedSocketTCPQuickAck
	NamedSocketTCPSyncNT
	NamedSocketTCPWindowClamp
	NamedSocketTCPNoPush
	NamedSocketTCPNoOpt
	NamedSocketSCTPNoDelay
	NamedSocketSCTPMaxSeg
	NamedSocketTCPMaxSegLate
	NamedSocketFIOSetown
	NamedSocketSIOCSPGRP
)

// AncillaryOption identifies one receive or send-side IP request.
type AncillaryOption uint8

const (
	AncillaryTimestamp AncillaryOption = iota + 1
	AncillaryIPv4PacketInfo
	AncillaryIPv4RecvTTL
	AncillaryIPv4RecvTOS
	AncillaryIPv4RecvOptions
	AncillaryIPv4RetOptions
	AncillaryIPv4RecvDstAddr
	AncillaryIPv4RecvInterface
	AncillaryIPv6PacketInfo
	AncillaryIPv6RecvHopLimit
	AncillaryIPv6RecvTrafficClass
	AncillaryIPv6RecvDstOptions
	AncillaryIPv6RecvHopOptions
	AncillaryIPv6RecvRoutingHeader
	AncillaryIPv6RecvPathMTU
	AncillaryIPv4TTL
	AncillaryIPv4TOS
	AncillaryIPv4Options
	AncillaryIPv4HeaderIncluded
	AncillaryIPv6UnicastHops
	AncillaryIPv6TrafficClass
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
)

// MulticastRequest is parsed once and resolves named interfaces at application
// time. Group and interface names remain intentionally unresolved.
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
}

// SourceMulticastRequest is an unresolved source-specific membership request.
type SourceMulticastRequest struct {
	IPv6      bool
	Name      string
	Group     HostTarget
	Source    HostTarget
	Interface HostTarget
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
	Named     NamedSocketOption
	Ancillary AncillaryOption
	Number    int
	Option    int
	Duration  time.Duration
	Text      string
	Value     SocketValue
	Multicast MulticastRequest
	Source    SourceMulticastRequest
}

// RawSocketCall holds a generic SOCKET positional call after syntactic
// decoding. It has no string form that execution must parse.
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

// VSOCKSettings holds generic VSOCK socket parameters and endpoints.
type VSOCKSettings struct {
	Connect VSOCKEndpoint
	Listen  uint32
	Bind    VSOCKEndpoint
	BindSet bool
}

// TUNType chooses the Linux TUN device mode.
type TUNType uint8

const (
	TUNTypeTUN TUNType = iota + 1
	TUNTypeTAP
)

// TUNSettings holds static TUN and interface configuration.
type TUNSettings struct {
	Address      netip.Prefix
	AddressSet   bool
	Device       string
	Name         string
	Type         TUNType
	NoPacketInfo OptionalBool
	InterfaceSet uint16
	InterfaceClr uint16
	MTU          OptionalUint32
	RetrieveVLAN bool
}

// POSIXMQSettings holds the static POSIX message-queue options.
type POSIXMQSettings struct {
	Priority    OptionalUint32
	Flush       OptionalBool
	MaxMessages OptionalInt
	MessageSize OptionalInt
}

// PeerPolicy holds prepared peer filtering inputs. Range names remain
// unresolved because they must use the selected resolver at open time.
// TCPWrapDaemon is the optional hosts-table service name from tcpwrap=<daemon>
// and keeps its original spelling.
type PeerPolicy struct {
	Range         string
	RangeSet      bool
	SourcePort    PortTarget
	SourcePortSet bool
	LowPort       OptionalBool
	TCPWrap       OptionalBool
	TCPWrapDaemon string
	TCPWrapEtc    OptionalString
	HostsAllow    OptionalString
	HostsDeny     OptionalString
}

// WithoutSourcePort returns a copy that does not filter by source port.
// UDP DATAGRAM uses sourceport as a dest-port receive filter instead.
func (p PeerPolicy) WithoutSourcePort() PeerPolicy {
	p.SourcePort = PortTarget{}
	p.SourcePortSet = false
	return p
}

// Network contains the immutable network and socket configuration.
type Network struct {
	Kind   AddressKind
	Role   AddressRole
	Family AddressFamily

	Target     HostTarget
	TargetPort PortTarget
	TargetSet  bool
	ListenPort PortTarget
	ListenSet  bool
	Bind       HostTarget
	BindPort   PortTarget
	BindSet    bool

	ProtocolFamily int
	ProtocolSet    bool
	SocketType     OptionalInt
	SocketProtocol OptionalInt
	ReuseAddr      OptionalBool
	ReusePort      OptionalBool
	RawSocket      RawSocketCall
	RawBind        []byte
	RawBindSet     bool

	Peer    PeerPolicy
	Actions []SocketAction
	VSOCK   VSOCKSettings
	TUN     TUNSettings
	POSIXMQ POSIXMQSettings
}

func decodeNetwork(a *Address, spec parse.Spec) error {
	n := &a.Network
	n.Kind = addressKind(a.Facts.Group)
	n.Role = addressRole(a.Type)
	n.Family = addressFamily(a.Type)
	n.TUN.Type = TUNTypeTUN

	switch n.Kind {
	case AddressKindTCP, AddressKindUDP, AddressKindSCTP:
		switch n.Role {
		case AddressRoleConnect, AddressRoleSendTo, AddressRoleDatagram:
			if len(a.Params) >= 2 && a.Params[0] != "" && a.Params[1] != "" {
				n.Target = targetFromText(a.Params[0])
				n.TargetPort = portTarget(a.Params[1])
				n.TargetSet = true
			}
		case AddressRoleListen, AddressRoleReceive, AddressRoleReceiveFrom:
			if len(a.Params) >= 1 && a.Params[0] != "" {
				n.ListenPort = portTarget(a.Params[0])
				n.ListenSet = true
			}
		}
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
				n.VSOCK.Listen = port
			}
		} else if len(a.Params) == 2 {
			cid, err := vsockCID(a.Params[0])
			if err != nil {
				return fmt.Errorf("%s: cid: %w", a.Type, err)
			}
			port, err := vsockUint32(a.Params[1])
			if err != nil {
				return fmt.Errorf("%s: port: %w", a.Type, err)
			}
			n.VSOCK.Connect = VSOCKEndpoint{CID: cid, Port: port}
		}
	case AddressKindSocket:
		if err := decodeRawSocketCall(a, spec); err != nil {
			return err
		}
	case AddressKindTUN:
		if err := decodeTUNPositional(a); err != nil {
			return err
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
		a.Common.ConnectBind = OptionalString{Set: true, Value: text}
		if n.Kind == AddressKindSocket {
			data, err := parseSocketData(text)
			if err != nil {
				return true, err
			}
			n.RawBind, n.RawBindSet = data, true
			return true, nil
		}
		n.Bind = targetFromText(text)
		n.BindSet = true
		return true, nil
	case "sourceport":
		text := optionText(o)
		a.Common.SourcePort = OptionalString{Set: true, Value: text}
		n.Peer.SourcePort = portTarget(text)
		n.Peer.SourcePortSet = true
		return true, nil
	case "lowport":
		n.Peer.LowPort = activeBool(o)
		return true, nil
	case "range":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		n.Peer.Range, n.Peer.RangeSet = value, true
		return true, nil
	case "tcpwrap":
		n.Peer.TCPWrap = activeBool(o)
		n.Peer.TCPWrapDaemon = ""
		if o.Has && o.Value != "" && o.Value != "1" {
			n.Peer.TCPWrapDaemon = o.Value
		}
		return true, nil
	case "tcpwrap-etc":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		n.Peer.TCPWrapEtc = OptionalString{Set: true, Value: value}
		return true, nil
	case "hosts-allow":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		n.Peer.HostsAllow = OptionalString{Set: true, Value: value}
		return true, nil
	case "hosts-deny":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		n.Peer.HostsDeny = OptionalString{Set: true, Value: value}
		return true, nil
	case "pf":
		text := optionText(o)
		a.Common.ProtocolFamily = OptionalString{Set: true, Value: text}
		pf, known, err := protocolFamily(text)
		if err != nil {
			return true, err
		}
		if !known && (n.Kind == AddressKindSocket || n.Kind == AddressKindVSOCK) {
			return true, fmt.Errorf("unknown protocol family %q", text)
		}
		if known {
			n.ProtocolFamily, n.ProtocolSet = pf, true
		}
		return true, nil
	case "socktype":
		value, err := requiredSocketInt(o, "socktype")
		if err != nil {
			return true, err
		}
		n.SocketType = OptionalInt{Set: true, Value: value}
		return true, nil
	case "so-protocol":
		value, err := requiredSocketInt(o, "so-protocol")
		if err != nil {
			return true, err
		}
		n.SocketProtocol = OptionalInt{Set: true, Value: value}
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
		n.ReuseAddr = activeBool(o)
		return true, nil
	case "reuseport":
		n.ReusePort = activeBool(o)
		return true, nil
	case "ipv6-v6only":
		v, err := optionalBool(o)
		a.Common.IPv6V6Only = v
		return true, err
	}
	if action, ok, err := socketAction(o, name); ok {
		if err != nil {
			return true, err
		}
		n.Actions = append(n.Actions, action)
		if action.Kind == SocketActionTimeout {
			opt := OptionalDuration{Set: true, Value: action.Duration}
			if action.Text == "rcvtimeo" {
				a.Common.Timeouts.Read = opt
			} else {
				a.Common.Timeouts.Write = opt
			}
		}
		return true, nil
	}
	if handled, err := decodeTUNOption(&n.TUN, o, name); handled {
		return true, err
	}
	if handled, err := decodePOSIXMQOption(&n.POSIXMQ, o, name); handled {
		return true, err
	}
	return false, nil
}

func addressKind(group string) AddressKind {
	switch group {
	case "TCP":
		return AddressKindTCP
	case "UDP":
		return AddressKindUDP
	case "Raw IP":
		return AddressKindRawIP
	case "Generic socket":
		return AddressKindSocket
	case "SCTP (Linux)":
		return AddressKindSCTP
	case "VSOCK (Linux)":
		return AddressKindVSOCK
	case "Linux TUN / INTERFACE":
		return AddressKindTUN
	case "POSIX message queues (Linux)":
		return AddressKindPOSIXMQ
	default:
		return AddressKindOther
	}
}

func addressRole(typ string) AddressRole {
	switch typ {
	case "TCP", "TCP-CONNECT", "TCP4", "TCP4-CONNECT", "TCP6", "TCP6-CONNECT",
		"UDP", "UDP-CONNECT", "UDP4", "UDP4-CONNECT", "UDP6", "UDP6-CONNECT",
		"SCTP", "SCTP-CONNECT", "SCTP4", "SCTP4-CONNECT", "SCTP6", "SCTP6-CONNECT",
		"VSOCK", "VSOCK-CONNECT", "SOCKET-CONNECT":
		return AddressRoleConnect
	case "TCP-LISTEN", "TCP-L", "TCP4-LISTEN", "TCP4-L", "TCP6-LISTEN", "TCP6-L",
		"UDP-LISTEN", "UDP-L", "UDP4-LISTEN", "UDP4-L", "UDP6-LISTEN", "UDP6-L",
		"SCTP-LISTEN", "SCTP-L", "SCTP4-LISTEN", "SCTP4-L", "SCTP6-LISTEN", "SCTP6-L",
		"VSOCK-LISTEN", "VSOCK-L", "SOCKET-LISTEN":
		return AddressRoleListen
	case "UDP-SENDTO", "UDP-SEND", "UDP4-SENDTO", "UDP4-SEND", "UDP6-SENDTO", "UDP6-SEND",
		"IP-SENDTO", "IP-SEND", "IP4-SENDTO", "IP4-SEND", "IP6-SENDTO", "IP6-SEND",
		"SOCKET-SENDTO":
		return AddressRoleSendTo
	case "UDP-DATAGRAM", "UDP4-DATAGRAM", "UDP6-DATAGRAM",
		"IP-DATAGRAM", "IP4-DATAGRAM", "IP6-DATAGRAM", "SOCKET-DATAGRAM":
		return AddressRoleDatagram
	case "UDP-RECV", "UDP4-RECV", "UDP6-RECV", "IP-RECV", "IP4-RECV", "IP6-RECV", "SOCKET-RECV":
		return AddressRoleReceive
	case "UDP-RECVFROM", "UDP4-RECVFROM", "UDP6-RECVFROM",
		"IP-RECVFROM", "IP4-RECVFROM", "IP6-RECVFROM", "SOCKET-RECVFROM":
		return AddressRoleReceiveFrom
	default:
		return AddressRoleOther
	}
}

func addressFamily(typ string) AddressFamily {
	switch typ {
	case "TCP4", "TCP4-CONNECT", "TCP4-LISTEN", "TCP4-L",
		"UDP4", "UDP4-CONNECT", "UDP4-LISTEN", "UDP4-L", "UDP4-SENDTO", "UDP4-SEND",
		"UDP4-DATAGRAM", "UDP4-RECV", "UDP4-RECVFROM",
		"IP4", "IP4-SENDTO", "IP4-SEND", "IP4-DATAGRAM", "IP4-RECV", "IP4-RECVFROM",
		"SCTP4", "SCTP4-CONNECT", "SCTP4-LISTEN", "SCTP4-L":
		return AddressFamilyIPv4
	case "TCP6", "TCP6-CONNECT", "TCP6-LISTEN", "TCP6-L",
		"UDP6", "UDP6-CONNECT", "UDP6-LISTEN", "UDP6-L", "UDP6-SENDTO", "UDP6-SEND",
		"UDP6-DATAGRAM", "UDP6-RECV", "UDP6-RECVFROM",
		"IP6", "IP6-SENDTO", "IP6-SEND", "IP6-DATAGRAM", "IP6-RECV", "IP6-RECVFROM",
		"SCTP6", "SCTP6-CONNECT", "SCTP6-LISTEN", "SCTP6-L":
		return AddressFamilyIPv6
	default:
		return AddressFamilyAny
	}
}

func targetFromText(text string) HostTarget {
	text = stripBrackets(text)
	if ip, err := netip.ParseAddr(text); err == nil {
		return HostTarget{Literal: ip}
	}
	return HostTarget{Name: text}
}

func portTarget(text string) PortTarget {
	if n, err := strconv.ParseUint(text, 10, 16); err == nil {
		return PortTarget{Number: uint16(n), Numeric: true}
	}
	return PortTarget{Service: text}
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

func socketPositionalInt(value string) (int, error) {
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
		domain, err := socketPositionalInt(a.Params[0])
		if err != nil {
			return fmt.Errorf("domain: %w", err)
		}
		proto, err := socketPositionalInt(a.Params[1])
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
	domain, err := socketPositionalInt(a.Params[0])
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
	proto, err := socketPositionalInt(a.Params[2])
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
	return parseSocketData(text)
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

func parseSocketData(value string) ([]byte, error) {
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
		more, err := parseSocketData(rest)
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
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	negative := value[0] == '-'
	if negative || value[0] == '+' {
		value = value[1:]
	}
	n, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		return 0, err
	}
	if negative {
		n = -n
	}
	return uint32(n), nil // #nosec G115 -- VSOCK uses the C uint32_t conversion
}

func vsockCID(value string) (uint32, error) {
	if value == "" {
		return ^uint32(0), nil
	}
	return vsockUint32(value)
}

func decodeTUNPositional(a *Address) error {
	if len(a.Params) == 0 {
		return nil
	}
	if len(a.Params) != 1 || a.Params[0] == "" {
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
	a.Network.TUN.Address, a.Network.TUN.AddressSet = prefix, true
	return nil
}

func decodeTUNOption(t *TUNSettings, o parse.Option, name string) (bool, error) {
	switch name {
	case "tun-device":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		t.Device = value
	case "tun-name":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		t.Name = value
	case "tun-type":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		switch strings.ToLower(value) {
		case "tun":
			t.Type = TUNTypeTUN
		case "tap":
			t.Type = TUNTypeTAP
		default:
			return true, fmt.Errorf("unknown tun-type %q", value)
		}
	case "iff-no-pi":
		t.NoPacketInfo = activeBool(o)
	case "if-mtu":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		n, err := strconv.ParseUint(value, 0, 32)
		if err != nil || n == 0 {
			return true, fmt.Errorf("if-mtu: invalid %q", value)
		}
		t.MTU = OptionalUint32{Set: true, Value: uint32(n)}
	case "retrieve-vlan":
		if o.Has {
			return true, fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
		t.RetrieveVLAN = true
	default:
		bit, ok := interfaceFlagBit(name)
		if !ok {
			return false, nil
		}
		if activeBool(o).Value {
			t.InterfaceSet |= bit
		} else {
			t.InterfaceClr |= bit
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

func decodePOSIXMQOption(m *POSIXMQSettings, o parse.Option, name string) (bool, error) {
	switch name {
	case "mq-prio":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		n, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return true, fmt.Errorf("invalid mq-prio %q", value)
		}
		m.Priority = OptionalUint32{Set: true, Value: uint32(n)}
	case "mq-flush":
		m.Flush = activeBool(o)
	case "mq-maxmsg", "mq-msgsize":
		n, err := requiredInt(o, 0)
		if err != nil {
			return true, err
		}
		if name == "mq-maxmsg" {
			m.MaxMessages = OptionalInt{Set: true, Value: n}
		} else {
			m.MessageSize = OptionalInt{Set: true, Value: n}
		}
	default:
		return false, nil
	}
	return true, nil
}
