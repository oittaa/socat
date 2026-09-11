package addrconfig

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

func socketAction(o parse.Option, name string) (SocketAction, bool, error) {
	switch name {
	case "setsockopt-listen", "setsockopt-socket", "setsockopt", "setsockopt-bin",
		"setsockopt-int", "setsockopt-string", "setsockopt-connected":
		action, err := genericSocketAction(o, name)
		return action, true, err
	case "broadcast":
		return optionalIntAction(SocketActionBroadcast, SocketPhasePastSocket, o, name, 1)
	case "sndbuf", "rcvbuf", "sndbuf-late", "rcvbuf-late":
		phase := SocketPhasePastSocket
		if strings.HasSuffix(name, "-late") {
			phase = SocketPhaseLate
		}
		action, ok, err := requiredIntAction(SocketActionBuffer, phase, o, name)
		if err == nil {
			action.Recv = strings.HasPrefix(name, "rcv")
		}
		return action, ok, err
	case "bindtodevice":
		value, err := requiredString(o)
		if err != nil {
			return SocketAction{}, true, err
		}
		return SocketAction{Kind: SocketActionBindToDevice, Phase: SocketPhasePastSocket, Text: value}, true, nil
	case "so-linger":
		return requiredIntAction(SocketActionLinger, SocketPhasePastSocket, o, name)
	case "rcvtimeo", "sndtimeo":
		value, err := duration(o)
		if err != nil {
			return SocketAction{}, true, err
		}
		return SocketAction{Kind: SocketActionTimeout, Phase: SocketPhasePastSocket, Text: name, Duration: value, Recv: name == "rcvtimeo"}, true, nil
	case "ip-add-membership", "ipv6-join-group", "ip-multicast-if", "ip-multicast-loop",
		"ip-multicast-ttl", "ipv6-multicast-loop":
		request, err := decodeMulticastRequest(o, multicastKind(name), name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, true, err
	case "ip-add-source-membership", "ipv6-join-source-group":
		request, err := decodeSourceMulticastRequest(o, name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, true, err
	case "ip-freebind":
		return optionalIntAction(SocketActionFreebind, SocketPhasePrebind, o, name, 1)
	case "ip-transparent":
		return optionalIntAction(SocketActionTransparent, SocketPhasePrebind, o, name, 1)
	case "ip-mtu-discover", "ipv6-mtu-discover":
		n, err := requiredSocketInt(o, name)
		if err != nil || n < 0 || n > 2 {
			return SocketAction{}, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
		}
		return SocketAction{Kind: SocketActionMTUDiscovery, Phase: SocketPhasePastSocket, Text: name, Number: n, IPv6: name == "ipv6-mtu-discover"}, true, nil
	case "ip-recverr", "ipv6-recverr":
		n, err := ancillaryOptionInt(o)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("%s: %w", name, err)
		}
		return SocketAction{Kind: SocketActionRecvErr, Phase: SocketPhasePastSocket, Text: name, Number: n, IPv6: name == "ipv6-recverr"}, true, nil
	case "ip-router-alert":
		return optionalIntAction(SocketActionRouterAlert, SocketPhasePastSocket, o, name, 1)
	case "ip-mtu", "ip-pktoptions":
		id := IPGetOnlyMTU
		if name == "ip-pktoptions" {
			id = IPGetOnlyPktoptions
		}
		return SocketAction{Kind: SocketActionGetOnly, Phase: SocketPhasePastSocket, GetOnly: id, Text: name}, true, nil
	}
	if id := namedSocketID(name); id != NamedSocketNone {
		n, err := optionalNamedSocketInt(o, name)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
		}
		phase := SocketPhasePastSocket
		if id == NamedSocketTCPMaxSegLate {
			phase = SocketPhaseConnected
		}
		return SocketAction{Kind: SocketActionNamed, Phase: phase, Named: id, Number: n, Text: name}, true, nil
	}
	if ancillaryOption(name) {
		id := ancillaryID(name)
		if name == "ip-options" {
			value, err := requiredString(o)
			if err != nil {
				return SocketAction{}, true, err
			}
			data, _, err := ParseDalan(value, 'i')
			if err != nil {
				return SocketAction{}, true, fmt.Errorf("ip-options: %w", err)
			}
			if len(data) > 256 {
				return SocketAction{}, true, fmt.Errorf("ip-options: value exceeds 256 bytes")
			}
			return SocketAction{Kind: SocketActionAncillary, Phase: SocketPhasePastSocket, Ancillary: id, Text: name, Value: SocketValue{Bytes: data}}, true, nil
		}
		n, err := ancillaryOptionInt(o)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("%s: %w", name, err)
		}
		return SocketAction{Kind: SocketActionAncillary, Phase: SocketPhasePastSocket, Ancillary: id, Text: name, Number: n}, true, nil
	}
	return SocketAction{}, false, nil
}

func optionalIntAction(kind SocketActionKind, phase SocketPhase, o parse.Option, name string, fallback int) (SocketAction, bool, error) {
	n, err := optionalSocketInt(o, fallback)
	if err != nil || n < 0 {
		return SocketAction{}, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	return SocketAction{Kind: kind, Phase: phase, Text: name, Number: n}, true, nil
}

func requiredIntAction(kind SocketActionKind, phase SocketPhase, o parse.Option, name string) (SocketAction, bool, error) {
	n, err := requiredSocketInt(o, name)
	if err != nil || n < 0 {
		return SocketAction{}, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	return SocketAction{Kind: kind, Phase: phase, Text: name, Number: n}, true, nil
}

func genericSocketAction(o parse.Option, name string) (SocketAction, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return SocketAction{}, fmt.Errorf("%s requires level:optname:value", name)
	}
	parts := strings.SplitN(o.Value, ":", 3)
	if len(parts) != 3 {
		return SocketAction{}, fmt.Errorf("%s requires level:optname:value", name)
	}
	level, err := socketIntText(parts[0])
	if err != nil {
		return SocketAction{}, fmt.Errorf("%s level: %w", name, err)
	}
	opt, err := socketIntText(parts[1])
	if err != nil {
		return SocketAction{}, fmt.Errorf("%s optname: %w", name, err)
	}
	phase := SocketPhaseConnected
	switch name {
	case "setsockopt-listen":
		phase = SocketPhasePrebind
	case "setsockopt-socket":
		phase = SocketPhasePastSocket
	}
	var value SocketValue
	switch name {
	case "setsockopt-int":
		n, err := socketIntText(parts[2])
		if err != nil {
			return SocketAction{}, fmt.Errorf("%s value: %w", name, err)
		}
		value = SocketValue{IsInt: true, Int: n}
	case "setsockopt-string":
		value = SocketValue{Bytes: append([]byte(parts[2]), 0)}
	default:
		data, singleInt, err := ParseDalan(parts[2], 'i')
		if err != nil {
			return SocketAction{}, fmt.Errorf("%s value: %w", name, err)
		}
		if len(data) == 0 {
			return SocketAction{}, fmt.Errorf("%s value: empty dalan value", name)
		}
		if singleInt {
			value = SocketValue{IsInt: true, Int: nativeCInt(data)}
		} else {
			value = SocketValue{Bytes: data}
		}
	}
	return SocketAction{
		Kind:   SocketActionGeneric,
		Phase:  phase,
		Text:   name,
		Value:  value,
		Number: level,
		Option: opt,
	}, nil
}

func optionalSocketInt(o parse.Option, fallback int) (int, error) {
	if !o.Has {
		return fallback, nil
	}
	return socketIntText(o.Value)
}

func optionalNamedSocketInt(o parse.Option, name string) (int, error) {
	if name == "fiosetown" || name == "siocspgrp" {
		if !o.Has {
			return 1, nil
		}
		return classicCInt(o.Value)
	}
	return optionalSocketInt(o, 1)
}

func namedSocketID(name string) NamedSocket {
	switch name {
	case "so-debug":
		return NamedSocketDebug
	case "so-dontroute":
		return NamedSocketDontRoute
	case "so-oobinline":
		return NamedSocketOOBInline
	case "so-rcvlowat":
		return NamedSocketRcvLowat
	case "so-sndlowat":
		return NamedSocketSndLowat
	case "so-priority":
		return NamedSocketPriority
	case "so-passcred":
		return NamedSocketPassCred
	case "so-no-check":
		return NamedSocketNoCheck
	case "so-detach-filter":
		return NamedSocketDetachFilter
	case "tcp-cork":
		return NamedSocketTCPCork
	case "tcp-defer-accept":
		return NamedSocketTCPDeferAccept
	case "tcp-linger2":
		return NamedSocketTCPLinger2
	case "tcp-maxseg":
		return NamedSocketTCPMaxSeg
	case "tcp-quickack":
		return NamedSocketTCPQuickAck
	case "tcp-syncnt":
		return NamedSocketTCPSyncnt
	case "tcp-window-clamp":
		return NamedSocketTCPWindowClamp
	case "nopush", "tcp-nopush":
		return NamedSocketNoPush
	case "noopt", "tcp-noopt":
		return NamedSocketNoOpt
	case "sctp-nodelay":
		return NamedSocketSCTPNodelay
	case "sctp-maxseg":
		return NamedSocketSCTPMaxSeg
	case "tcp-maxseg-late":
		return NamedSocketTCPMaxSegLate
	case "fiosetown":
		return NamedSocketFIOSETOWN
	case "siocspgrp":
		return NamedSocketSIOCSPGRP
	default:
		return NamedSocketNone
	}
}

func ancillaryOption(name string) bool {
	return ancillaryID(name) != AncillaryNone
}

// AncillaryID is the typed identity of a canonical IP/ancillary option name.
func AncillaryID(name string) AncillaryOption { return ancillaryID(name) }

func ancillaryID(name string) AncillaryOption {
	switch name {
	case "so-timestamp":
		return AncillarySOTimestamp
	case "ip-pktinfo":
		return AncillaryIPPktinfo
	case "ip-recvttl":
		return AncillaryIPRecvTTL
	case "ip-recvtos":
		return AncillaryIPRecvTOS
	case "ip-recvopts":
		return AncillaryIPRecvOpts
	case "ip-retopts":
		return AncillaryIPRetOpts
	case "ip-recvdstaddr":
		return AncillaryIPRecvDstAddr
	case "ip-recvif":
		return AncillaryIPRecvIf
	case "ipv6-recvpktinfo":
		return AncillaryIPv6RecvPktinfo
	case "ipv6-recvhoplimit":
		return AncillaryIPv6RecvHopLimit
	case "ipv6-recvtclass":
		return AncillaryIPv6RecvTclass
	case "ipv6-recvdstopts":
		return AncillaryIPv6RecvDstOpts
	case "ipv6-recvhopopts":
		return AncillaryIPv6RecvHopOpts
	case "ipv6-recvrthdr":
		return AncillaryIPv6RecvRtHdr
	case "ipv6-recvpathmtu":
		return AncillaryIPv6RecvPathMTU
	case "ip-ttl":
		return AncillaryIPTTL
	case "ip-tos":
		return AncillaryIPTOS
	case "ip-options":
		return AncillaryIPOptions
	case "ip-hdrincl":
		return AncillaryIPHdrincl
	case "ipv6-unicast-hops":
		return AncillaryIPv6UnicastHops
	case "ipv6-tclass":
		return AncillaryIPv6Tclass
	default:
		return AncillaryNone
	}
}

func multicastKind(name string) MulticastKind {
	switch name {
	case "ipv6-join-group":
		return MulticastJoinIPv6
	case "ip-multicast-if":
		return MulticastInterfaceIPv4
	case "ip-multicast-loop":
		return MulticastLoopIPv4
	case "ip-multicast-ttl":
		return MulticastTTLIPv4
	case "ipv6-multicast-loop":
		return MulticastLoopIPv6
	default:
		return MulticastJoinIPv4
	}
}

func ancillaryOptionInt(o parse.Option) (int, error) {
	if !o.Has {
		return 1, nil
	}
	switch strings.ToLower(strings.TrimSpace(o.Value)) {
	case "", "0", "false", "no", "off":
		return 0, nil
	case "1", "true", "yes", "on":
		return 1, nil
	default:
		return socketIntText(o.Value)
	}
}

func decodeMulticastRequest(o parse.Option, kind MulticastKind, name string) (MulticastRequest, error) {
	request := MulticastRequest{Kind: kind, Name: name}
	if kind == MulticastLoopIPv4 || kind == MulticastLoopIPv6 || kind == MulticastTTLIPv4 {
		max := 255
		if kind != MulticastTTLIPv4 {
			max = 1
		}
		n, err := optionalSocketInt(o, 1)
		if err != nil || n < 0 || n > max {
			return request, fmt.Errorf("%s: invalid value %q", name, o.Value)
		}
		request.Value = n
		return request, nil
	}
	value, err := requiredString(o)
	if err != nil {
		return request, err
	}
	if kind == MulticastInterfaceIPv4 {
		request.InterfaceAddr = targetFromText(value)
		return request, nil
	}
	parts, err := splitMulticastFields(value)
	if err != nil {
		return request, fmt.Errorf("%s: %w", name, err)
	}
	if len(parts) < 2 || len(parts) > 3 {
		return request, fmt.Errorf("%s: expected mcast:iface, got %q", name, value)
	}
	request.Group = targetFromText(parts[0])
	if request.Group.String() == "" {
		return request, fmt.Errorf("%s: expected mcast:iface, got %q", name, value)
	}
	if len(parts) == 3 {
		if kind == MulticastJoinIPv6 {
			return request, fmt.Errorf("%s: three-field form is IPv4-only", name)
		}
		request.ThreeField = true
		request.InterfaceAddr = targetFromText(parts[1])
		request.InterfaceName, request.InterfaceID, request.InterfaceIsID = multicastInterface(parts[2])
	} else {
		request.InterfaceName, request.InterfaceID, request.InterfaceIsID = multicastInterface(parts[1])
	}
	if request.InterfaceName == "" && !request.InterfaceIsID && !request.InterfaceAddr.IsLiteral() && request.InterfaceAddr.Name == "" {
		return request, fmt.Errorf("%s: expected mcast:iface, got %q", name, value)
	}
	return request, nil
}

func decodeSourceMulticastRequest(o parse.Option, name string) (MulticastRequest, error) {
	kind := MulticastSourceIPv4
	if name == "ipv6-join-source-group" {
		kind = MulticastSourceIPv6
	}
	value, err := requiredString(o)
	if err != nil {
		return MulticastRequest{}, err
	}
	parts, err := splitMulticastFields(value)
	if err != nil || len(parts) != 3 {
		return MulticastRequest{}, fmt.Errorf("%s: expected group:iface:source, got %q", name, value)
	}
	return MulticastRequest{
		Kind:          kind,
		Name:          name,
		Group:         targetFromText(parts[0]),
		InterfaceAddr: targetFromText(parts[1]),
		Source:        targetFromText(parts[2]),
	}, nil
}

func splitMulticastFields(value string) ([]string, error) {
	if i := strings.IndexByte(value, '%'); i > 0 && !strings.Contains(value, ":") {
		return []string{value[:i], value[i+1:]}, nil
	}
	var out []string
	var valueBuilder strings.Builder
	depth := 0
	for i := range value {
		switch value[i] {
		case '[':
			depth++
			valueBuilder.WriteByte(value[i])
		case ']':
			if depth > 0 {
				depth--
			}
			valueBuilder.WriteByte(value[i])
		case ':':
			if depth == 0 {
				out = append(out, strings.TrimSpace(valueBuilder.String()))
				valueBuilder.Reset()
				continue
			}
			valueBuilder.WriteByte(value[i])
		default:
			valueBuilder.WriteByte(value[i])
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unclosed bracket")
	}
	out = append(out, strings.TrimSpace(valueBuilder.String()))
	return out, nil
}

func multicastInterface(value string) (string, uint32, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, false
	}
	unsigned := value
	if unsigned[0] == '+' || unsigned[0] == '-' {
		unsigned = unsigned[1:]
	}
	if unsigned == "" || strings.ContainsRune(unsigned, '_') ||
		strings.HasPrefix(unsigned, "0b") || strings.HasPrefix(unsigned, "0B") ||
		strings.HasPrefix(unsigned, "0o") || strings.HasPrefix(unsigned, "0O") {
		return value, 0, false
	}
	n, err := strconv.ParseInt(value, 0, strconv.IntSize)
	if err != nil {
		return value, 0, false
	}
	return "", uint32(n), true // #nosec G115 -- membership uses the C unsigned index conversion
}

// ParseDalan packs typed items at native width. singleInt is one C int.
func ParseDalan(value string, defaultType byte) ([]byte, bool, error) {
	if defaultType == 0 {
		defaultType = 'i'
	}
	line := value
	var data []byte
	items := 0
	onlyInt := true
	for line != "" {
		itemType := line[0]
		rest := line[1:]
		out, next, status := parseDalanItem(itemType, rest)
		switch status {
		case socketDalanOK:
			defaultType = itemType
		case socketDalanSpace:
			line = rest
			continue
		case socketDalanNotType:
			out, next, status = parseDalanItem(defaultType, line)
			if status != socketDalanOK || next == line {
				return nil, false, fmt.Errorf("syntax error in %q", value)
			}
			itemType = defaultType
		default:
			return nil, false, fmt.Errorf("syntax error in %q", value)
		}
		data = append(data, out...)
		line = next
		items++
		if itemType != 'i' {
			onlyInt = false
		}
	}
	return data, items == 1 && onlyInt && len(data) == 4, nil
}

const (
	socketDalanOK = iota
	socketDalanSyntax
	socketDalanSpace
	socketDalanNotType
)

func parseDalanItem(itemType byte, line string) ([]byte, string, int) {
	switch itemType {
	case ' ', '\t', '\r', '\n':
		return nil, line, socketDalanSpace
	case '"':
		data, rest, err := parseSocketString(`"` + line)
		if err != nil {
			return nil, line, socketDalanSyntax
		}
		return data, rest, socketDalanOK
	case '\'':
		if line == "" {
			return nil, line, socketDalanSyntax
		}
		value := line[0]
		line = line[1:]
		if value == '\\' {
			if line == "" {
				return nil, line, socketDalanSyntax
			}
			value, line = socketEscapeByte(line[0]), line[1:]
		}
		if line == "" || line[0] != '\'' {
			return nil, line, socketDalanSyntax
		}
		return []byte{value}, line[1:], socketDalanOK
	case 'x':
		var out []byte
		for len(line) >= 2 && hexDigit(line[0]) {
			if !hexDigit(line[1]) {
				return nil, line, socketDalanSyntax
			}
			data, err := hex.DecodeString(line[:2])
			if err != nil {
				return nil, line, socketDalanSyntax
			}
			out = append(out, data...)
			line = line[2:]
		}
		if len(line) > 0 && hexDigit(line[0]) {
			return nil, line, socketDalanSyntax
		}
		return out, line, socketDalanOK
	case 'l', 'L':
		return parseDalanNumber(line, cLongSize)
	case 'i', 'I':
		return parseDalanNumber(line, 4)
	case 's', 'S':
		return parseDalanNumber(line, 2)
	case 'b':
		first, remaining, status := parseDalanNumber(line, 1)
		if status != socketDalanOK {
			return nil, line, status
		}
		second, next, status := parseDalanNumber(remaining, 1)
		if status != socketDalanOK {
			second, next = []byte{0}, remaining
		}
		return append(first, second...), next, socketDalanOK
	case 'B':
		return parseDalanNumber(line, 1)
	default:
		return nil, line, socketDalanNotType
	}
}

func hexDigit(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func parseDalanNumber(line string, bytes int) ([]byte, string, int) {
	value, rest, ok := parseDalanInteger(line)
	if !ok {
		return nil, line, socketDalanSyntax
	}
	return encodeNative(uint64(value), bytes), rest, socketDalanOK // #nosec G115 -- C two's complement storage
}

func parseDalanInteger(line string) (int64, string, bool) {
	index := 0
	for index < len(line) && strings.ContainsRune(" \t\r\n", rune(line[index])) {
		index++
	}
	start := index
	if index < len(line) && (line[index] == '+' || line[index] == '-') {
		index++
	}
	digits := index
	for index < len(line) && line[index] >= '0' && line[index] <= '9' {
		index++
	}
	if index == digits {
		return 0, line, false
	}
	value, err := strconv.ParseInt(line[start:index], 10, 64)
	if err == nil {
		return value, line[index:], true
	}
	unsigned, unsignedErr := strconv.ParseUint(line[start:index], 10, 64)
	if unsignedErr != nil {
		return 0, line, false
	}
	return int64(unsigned), line[index:], true // #nosec G115 -- C two's complement storage
}

func encodeNative(value uint64, bytes int) []byte {
	data := make([]byte, bytes)
	switch bytes {
	case 1:
		data[0] = byte(value) // #nosec G115 -- C byte storage
	case 2:
		binary.NativeEndian.PutUint16(data, uint16(value)) // #nosec G115 -- C short storage
	case 4:
		binary.NativeEndian.PutUint32(data, uint32(value)) // #nosec G115 -- C int storage
	case 8:
		binary.NativeEndian.PutUint64(data, value)
	}
	return data
}

func nativeCInt(data []byte) int {
	if len(data) < 4 {
		return 0
	}
	return int(int32(binary.NativeEndian.Uint32(data[:4]))) // #nosec G115 -- native C int bytes
}
