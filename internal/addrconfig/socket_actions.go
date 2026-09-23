package addrconfig

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

type sockoptMode uint8

const (
	sockoptDalan sockoptMode = iota
	sockoptInt
	sockoptString
)

func socketAction(kind optionmeta.Kind, o parse.Option, name, kernel string) (SocketAction, error) {
	switch kind {
	case optionmeta.KindSockoptDalan, optionmeta.KindSockoptInt, optionmeta.KindSockoptString:
		mode := sockoptDalan
		switch kind {
		case optionmeta.KindSockoptInt:
			mode = sockoptInt
		case optionmeta.KindSockoptString:
			mode = sockoptString
		}
		return genericSocketAction(o, name, mode)
	case optionmeta.KindWordInt:
		id, phase := SocketActionBroadcast, SocketPhasePastSocket
		if name == "ip-freebind" {
			id, phase = SocketActionFreebind, SocketPhasePrebind
		}
		return optionalWordIntAction(id, phase, o, name, 1)
	case optionmeta.KindBuffer:
		phase := SocketPhasePastSocket
		if strings.HasSuffix(name, "-late") {
			phase = SocketPhaseLate
		}
		action, err := requiredIntAction(SocketActionBuffer, phase, o, name)
		if err == nil {
			action.Recv = strings.HasPrefix(name, "rcv")
		}
		return action, err
	case optionmeta.KindBindDevice:
		value, err := requiredString(o)
		if err != nil {
			return SocketAction{}, err
		}
		return SocketAction{Kind: SocketActionBindToDevice, Phase: SocketPhasePastSocket, Text: value}, nil
	case optionmeta.KindLinger:
		return requiredIntAction(SocketActionLinger, SocketPhasePastSocket, o, name)
	case optionmeta.KindTimeout:
		value, err := duration(o)
		if err != nil {
			return SocketAction{}, err
		}
		return SocketAction{Kind: SocketActionTimeout, Phase: SocketPhasePastSocket, Text: name, Duration: value, Recv: name == "rcvtimeo"}, nil
	case optionmeta.KindMcastJoin4, optionmeta.KindMcastJoin6, optionmeta.KindMcastIf, optionmeta.KindMcastLoop4, optionmeta.KindMcastTTL, optionmeta.KindMcastLoop6:
		request, err := decodeMulticastRequest(o, multicastKindOf(kind), name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, err
	case optionmeta.KindMcastSource4, optionmeta.KindMcastSource6:
		request, err := decodeSourceMulticastRequest(o, name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, err
	case optionmeta.KindTransparent:
		v, err := parseBool(o)
		if err != nil {
			return SocketAction{}, err
		}
		n := 0
		if v.Value {
			n = 1
		}
		return SocketAction{Kind: SocketActionTransparent, Phase: SocketPhasePrebind, Text: name, Number: n}, nil
	case optionmeta.KindMTUDiscover:
		n, err := requiredSocketInt(o)
		if err != nil || n < 0 || n > 2 {
			if err != nil && (!o.Has || strings.TrimSpace(o.Value) == "") {
				return SocketAction{}, err
			}
			return SocketAction{}, optionValueError(o, "invalid value", strconv.Quote(o.Value))
		}
		return SocketAction{Kind: SocketActionMTUDiscovery, Phase: SocketPhasePastSocket, Text: name, Number: n, IPv6: name == "ipv6-mtu-discover"}, nil
	case optionmeta.KindRecvErr:
		n, err := ancillaryOptionInt(o)
		if err != nil {
			return SocketAction{}, err
		}
		return SocketAction{Kind: SocketActionRecvErr, Phase: SocketPhasePastSocket, Text: name, Number: n, IPv6: name == "ipv6-recverr"}, nil
	case optionmeta.KindRouterAlert:
		return optionalIntAction(SocketActionRouterAlert, SocketPhasePastSocket, o, name, 1)
	case optionmeta.KindGetOnly:
		id := IPGetOnlyMTU
		if name == "ip-pktoptions" {
			id = IPGetOnlyPktoptions
		}
		return SocketAction{Kind: SocketActionGetOnly, Phase: SocketPhasePastSocket, GetOnly: id, Kernel: kernel, Text: name}, nil
	case optionmeta.KindNamedWord, optionmeta.KindNamedInt, optionmeta.KindNamedCInt:
		return namedSocketAction(kind, o, name)
	case optionmeta.KindIPOptions:
		return ipOptionsAction(o, name)
	case optionmeta.KindAncillary:
		n, err := ancillaryOptionInt(o)
		if err != nil {
			return SocketAction{}, err
		}
		return SocketAction{Kind: SocketActionAncillary, Phase: SocketPhasePastSocket, Ancillary: ancillaryID(name), Text: name, Number: n}, nil
	default:
		return SocketAction{}, nil
	}
}

func multicastKindOf(kind optionmeta.Kind) MulticastKind {
	switch kind {
	case optionmeta.KindMcastJoin6:
		return MulticastJoinIPv6
	case optionmeta.KindMcastIf:
		return MulticastInterfaceIPv4
	case optionmeta.KindMcastLoop4:
		return MulticastLoopIPv4
	case optionmeta.KindMcastTTL:
		return MulticastTTLIPv4
	case optionmeta.KindMcastLoop6:
		return MulticastLoopIPv6
	default:
		return MulticastJoinIPv4
	}
}

func namedSocketAction(kind optionmeta.Kind, o parse.Option, name string) (SocketAction, error) {
	var n int
	var err error
	switch kind {
	case optionmeta.KindNamedWord:
		n, err = parseIntOrBoolWord(o, 1)
	case optionmeta.KindNamedCInt:
		n, err = namedCInt(o)
	default:
		n, err = optionalSocketInt(o, 1)
		if err != nil {
			err = optionValueError(o, "invalid value", strconv.Quote(o.Value))
		}
	}
	if err != nil {
		return SocketAction{}, err
	}
	id := namedSocketID(name)
	phase := SocketPhasePastSocket
	if id == NamedSocketTCPMaxSegLate {
		phase = SocketPhaseConnected
	}
	return SocketAction{Kind: SocketActionNamed, Phase: phase, Named: id, Number: n, Text: name}, nil
}

func namedCInt(o parse.Option) (int, error) {
	if !o.Has {
		return 1, nil
	}
	n, err := classicCInt(o.Value)
	if err != nil {
		return 0, optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	return n, nil
}

func ipOptionsAction(o parse.Option, name string) (SocketAction, error) {
	value, err := requiredString(o)
	if err != nil {
		return SocketAction{}, err
	}
	data, _, err := ParseDalan(value, 'i')
	if err != nil {
		return SocketAction{}, optionValueError(o, "invalid value", err.Error())
	}
	if len(data) > 256 {
		return SocketAction{}, optionValueError(o, "invalid value", "value exceeds 256 bytes")
	}
	return SocketAction{Kind: SocketActionAncillary, Phase: SocketPhasePastSocket, Ancillary: ancillaryID(name), Text: name, Value: SocketValue{Bytes: data}}, nil
}

func optionalIntAction(kind SocketActionKind, phase SocketPhase, o parse.Option, name string, fallback int) (SocketAction, error) {
	n, err := optionalSocketInt(o, fallback)
	if err != nil || n < 0 {
		return SocketAction{}, optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	return SocketAction{Kind: kind, Phase: phase, Text: name, Number: n}, nil
}

func optionalWordIntAction(kind SocketActionKind, phase SocketPhase, o parse.Option, name string, fallback int) (SocketAction, error) {
	n, err := parseIntOrBoolWord(o, fallback)
	if err != nil {
		return SocketAction{}, err
	}
	if n < 0 {
		return SocketAction{}, optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	return SocketAction{Kind: kind, Phase: phase, Text: name, Number: n}, nil
}

func requiredIntAction(kind SocketActionKind, phase SocketPhase, o parse.Option, name string) (SocketAction, error) {
	n, err := requiredSocketInt(o)
	if err != nil {
		return SocketAction{}, err
	}
	if n < 0 {
		return SocketAction{}, optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	return SocketAction{Kind: kind, Phase: phase, Text: name, Number: n}, nil
}

func genericSocketAction(o parse.Option, name string, mode sockoptMode) (SocketAction, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return SocketAction{}, optionValueError(o, "invalid value", "level:optname:value")
	}
	parts := strings.SplitN(o.Value, ":", 3)
	if len(parts) != 3 {
		return SocketAction{}, optionValueError(o, "invalid value", "level:optname:value")
	}
	level, err := socketIntText(parts[0])
	if err != nil {
		return SocketAction{}, optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	opt, err := socketIntText(parts[1])
	if err != nil {
		return SocketAction{}, optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	phase := SocketPhaseConnected
	switch name {
	case "setsockopt-listen":
		phase = SocketPhasePrebind
	case "setsockopt-socket":
		phase = SocketPhasePastSocket
	}
	var value SocketValue
	switch mode {
	case sockoptInt:
		n, err := socketIntText(parts[2])
		if err != nil {
			return SocketAction{}, optionValueError(o, "invalid value", strconv.Quote(o.Value))
		}
		value = SocketValue{IsInt: true, Int: n}
	case sockoptString:
		value = SocketValue{Bytes: append([]byte(parts[2]), 0)}
	default:
		data, singleInt, err := ParseDalan(parts[2], 'i')
		if err != nil {
			return SocketAction{}, optionValueError(o, "invalid value", err.Error())
		}
		if len(data) == 0 {
			return SocketAction{}, optionValueError(o, "invalid value", "empty dalan value")
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

func namedSocketID(name string) NamedSocket { return namedSocketByName[name] }

var namedSocketByName = map[string]NamedSocket{
	"so-debug":         NamedSocketDebug,
	"so-dontroute":     NamedSocketDontRoute,
	"so-oobinline":     NamedSocketOOBInline,
	"so-rcvlowat":      NamedSocketRcvLowat,
	"so-sndlowat":      NamedSocketSndLowat,
	"so-priority":      NamedSocketPriority,
	"so-passcred":      NamedSocketPassCred,
	"so-no-check":      NamedSocketNoCheck,
	"so-detach-filter": NamedSocketDetachFilter,
	"tcp-cork":         NamedSocketTCPCork,
	"tcp-defer-accept": NamedSocketTCPDeferAccept,
	"tcp-linger2":      NamedSocketTCPLinger2,
	"tcp-maxseg":       NamedSocketTCPMaxSeg,
	"tcp-quickack":     NamedSocketTCPQuickAck,
	"tcp-syncnt":       NamedSocketTCPSyncnt,
	"tcp-window-clamp": NamedSocketTCPWindowClamp,
	"nopush":           NamedSocketNoPush,
	"tcp-nopush":       NamedSocketNoPush,
	"noopt":            NamedSocketNoOpt,
	"tcp-noopt":        NamedSocketNoOpt,
	"sctp-nodelay":     NamedSocketSCTPNodelay,
	"sctp-maxseg":      NamedSocketSCTPMaxSeg,
	"tcp-maxseg-late":  NamedSocketTCPMaxSegLate,
	"fiosetown":        NamedSocketFIOSETOWN,
	"siocspgrp":        NamedSocketSIOCSPGRP,
}

func AncillaryID(name string) AncillaryOption { return ancillaryID(name) }

func ancillaryID(name string) AncillaryOption { return ancillaryByName[name] }

var ancillaryByName = map[string]AncillaryOption{
	"so-timestamp":      AncillarySOTimestamp,
	"ip-pktinfo":        AncillaryIPPktinfo,
	"ip-recvttl":        AncillaryIPRecvTTL,
	"ip-recvtos":        AncillaryIPRecvTOS,
	"ip-recvopts":       AncillaryIPRecvOpts,
	"ip-retopts":        AncillaryIPRetOpts,
	"ip-recvdstaddr":    AncillaryIPRecvDstAddr,
	"ip-recvif":         AncillaryIPRecvIf,
	"ipv6-recvpktinfo":  AncillaryIPv6RecvPktinfo,
	"ipv6-recvhoplimit": AncillaryIPv6RecvHopLimit,
	"ipv6-recvtclass":   AncillaryIPv6RecvTclass,
	"ipv6-recvdstopts":  AncillaryIPv6RecvDstOpts,
	"ipv6-recvhopopts":  AncillaryIPv6RecvHopOpts,
	"ipv6-recvrthdr":    AncillaryIPv6RecvRtHdr,
	"ipv6-recvpathmtu":  AncillaryIPv6RecvPathMTU,
	"ip-ttl":            AncillaryIPTTL,
	"ip-tos":            AncillaryIPTOS,
	"ip-options":        AncillaryIPOptions,
	"ip-hdrincl":        AncillaryIPHdrincl,
	"ipv6-unicast-hops": AncillaryIPv6UnicastHops,
	"ipv6-tclass":       AncillaryIPv6Tclass,
}

func ancillaryOptionInt(o parse.Option) (int, error) {
	return parseIntOrBoolWord(o, 1)
}

func decodeMulticastRequest(o parse.Option, kind MulticastKind, name string) (MulticastRequest, error) {
	request := MulticastRequest{Kind: kind, Name: name}
	if kind == MulticastLoopIPv4 || kind == MulticastLoopIPv6 {
		v, err := parseBool(o)
		if err != nil {
			return request, err
		}
		if v.Value {
			request.Value = 1
		}
		return request, nil
	}
	if kind == MulticastTTLIPv4 {
		if !o.Has || strings.TrimSpace(o.Value) == "" {
			return request, optionValueError(o, "requires a value", "")
		}
		n, err := socketIntText(o.Value)
		if err != nil || n < 0 || n > 255 {
			return request, optionValueError(o, "invalid value", strconv.Quote(o.Value))
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
		return request, optionValueError(o, "invalid value", err.Error())
	}
	if len(parts) < 2 || len(parts) > 3 {
		return request, optionValueError(o, "invalid value", fmt.Sprintf("expected mcast:iface, got %q", value))
	}
	request.Group = targetFromText(parts[0])
	if request.Group.String() == "" {
		return request, optionValueError(o, "invalid value", fmt.Sprintf("expected mcast:iface, got %q", value))
	}
	if len(parts) == 3 {
		if kind == MulticastJoinIPv6 {
			return request, optionValueError(o, "invalid value", "three-field form is IPv4-only")
		}
		request.ThreeField = true
		request.InterfaceAddr = targetFromText(parts[1])
		setInterfaceToken(&request, parts[2])
	} else {
		setInterfaceToken(&request, parts[1])
	}
	if request.InterfaceName == "" && !request.InterfaceIsID && !request.InterfaceAddr.IsLiteral() && request.InterfaceAddr.Name == "" {
		return request, optionValueError(o, "invalid value", fmt.Sprintf("expected mcast:iface, got %q", value))
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
		return MulticastRequest{}, optionValueError(o, "invalid value", fmt.Sprintf("expected group:iface:source, got %q", value))
	}
	request := MulticastRequest{
		Kind:   kind,
		Name:   name,
		Group:  targetFromText(parts[0]),
		Source: targetFromText(parts[2]),
	}
	if kind == MulticastSourceIPv6 {
		setInterfaceToken(&request, parts[1])
	} else {
		request.InterfaceAddr = targetFromText(parts[1])
	}
	return request, nil
}

// setInterfaceToken classifies an interface token once: a C integer is an
// index, an IPv4 literal is an address, and anything else is a name.
func setInterfaceToken(request *MulticastRequest, token string) {
	name, id, isID := multicastInterface(token)
	if isID {
		request.InterfaceID = id
		request.InterfaceIsID = true
		return
	}
	if ip, err := netip.ParseAddr(stripBrackets(name)); err == nil && ip.Is4() {
		request.InterfaceAddr = HostTarget{Literal: ip, Name: name}
		return
	}
	request.InterfaceName = name
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
