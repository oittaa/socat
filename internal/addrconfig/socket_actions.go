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
		n, err := optionalSocketInt(o, 1)
		if err != nil || n < 0 {
			return SocketAction{}, true, fmt.Errorf("broadcast: invalid value %q", o.Value)
		}
		return SocketAction{Kind: SocketActionBroadcast, Phase: SocketPhasePastSocket, Number: n}, true, nil
	case "sndbuf", "rcvbuf":
		n, err := requiredSocketInt(o, name)
		if err != nil || n < 0 {
			return SocketAction{}, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
		}
		return SocketAction{Kind: SocketActionBuffer, Phase: SocketPhasePastSocket, Text: name, Number: n}, true, nil
	case "sndbuf-late", "rcvbuf-late":
		n, err := requiredSocketInt(o, name)
		if err != nil || n < 0 {
			return SocketAction{}, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
		}
		return SocketAction{Kind: SocketActionBuffer, Phase: SocketPhaseLate, Text: name, Number: n}, true, nil
	case "bindtodevice":
		value, err := requiredString(o)
		if err != nil {
			return SocketAction{}, true, err
		}
		return SocketAction{Kind: SocketActionBindToDevice, Phase: SocketPhasePastSocket, Text: value}, true, nil
	case "so-linger":
		n, err := requiredSocketInt(o, name)
		if err != nil || n < 0 {
			return SocketAction{}, true, fmt.Errorf("so-linger: invalid value %q", o.Value)
		}
		return SocketAction{Kind: SocketActionLinger, Phase: SocketPhasePastSocket, Number: n}, true, nil
	case "rcvtimeo", "sndtimeo":
		value, err := duration(o)
		if err != nil {
			return SocketAction{}, true, err
		}
		return SocketAction{Kind: SocketActionTimeout, Phase: SocketPhasePastSocket, Text: name, Duration: value}, true, nil
	case "ip-add-membership":
		request, err := decodeMulticastRequest(o, MulticastJoinIPv4, name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, true, err
	case "ipv6-join-group":
		request, err := decodeMulticastRequest(o, MulticastJoinIPv6, name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, true, err
	case "ip-multicast-if":
		request, err := decodeMulticastRequest(o, MulticastInterfaceIPv4, name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, true, err
	case "ip-multicast-loop":
		request, err := decodeMulticastRequest(o, MulticastLoopIPv4, name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, true, err
	case "ip-multicast-ttl":
		request, err := decodeMulticastRequest(o, MulticastTTLIPv4, name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, true, err
	case "ipv6-multicast-loop":
		request, err := decodeMulticastRequest(o, MulticastLoopIPv6, name)
		return SocketAction{Kind: SocketActionMulticast, Phase: SocketPhasePastSocket, Multicast: request}, true, err
	case "ip-add-source-membership":
		request, err := decodeSourceMulticastRequest(o, false, name)
		return SocketAction{Kind: SocketActionSourceMulticast, Phase: SocketPhasePastSocket, Source: request}, true, err
	case "ipv6-join-source-group":
		request, err := decodeSourceMulticastRequest(o, true, name)
		return SocketAction{Kind: SocketActionSourceMulticast, Phase: SocketPhasePastSocket, Source: request}, true, err
	case "ip-freebind":
		n, err := optionalSocketInt(o, 1)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("ip-freebind: invalid value %q", o.Value)
		}
		return SocketAction{Kind: SocketActionFreebind, Phase: SocketPhasePrebind, Number: n}, true, nil
	case "ip-transparent":
		n, err := optionalSocketInt(o, 1)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("ip-transparent: invalid value %q", o.Value)
		}
		return SocketAction{Kind: SocketActionTransparent, Phase: SocketPhasePrebind, Number: n}, true, nil
	case "ip-mtu-discover", "ipv6-mtu-discover":
		n, err := requiredSocketInt(o, name)
		if err != nil || n < 0 || n > 2 {
			return SocketAction{}, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
		}
		return SocketAction{Kind: SocketActionMTUDiscovery, Phase: SocketPhasePastSocket, Text: name, Number: n}, true, nil
	case "ip-recverr", "ipv6-recverr":
		n, err := ancillaryOptionInt(o)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("%s: %w", name, err)
		}
		return SocketAction{Kind: SocketActionRecvErr, Phase: SocketPhasePastSocket, Text: name, Number: n}, true, nil
	case "ip-router-alert":
		n, err := optionalSocketInt(o, 1)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("ip-router-alert: invalid value %q", o.Value)
		}
		return SocketAction{Kind: SocketActionRouterAlert, Phase: SocketPhasePastSocket, Text: name, Number: n}, true, nil
	case "ip-mtu", "ip-pktoptions":
		return SocketAction{Kind: SocketActionGetOnly, Phase: SocketPhasePastSocket, Text: name}, true, nil
	}
	if named, ok := namedSocketOption(name); ok {
		n, err := optionalNamedSocketInt(o, named)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
		}
		phase := SocketPhasePastSocket
		if named == NamedSocketTCPMaxSegLate {
			phase = SocketPhaseConnected
		}
		return SocketAction{Kind: SocketActionNamed, Phase: phase, Named: named, Number: n}, true, nil
	}
	if ancillary, ok := ancillaryOption(name); ok {
		if ancillary == AncillaryIPv4Options {
			value, err := requiredString(o)
			if err != nil {
				return SocketAction{}, true, err
			}
			data, _, err := parseDalan(value, 'i')
			if err != nil {
				return SocketAction{}, true, fmt.Errorf("ip-options: %w", err)
			}
			if len(data) > 256 {
				return SocketAction{}, true, fmt.Errorf("ip-options: value exceeds 256 bytes")
			}
			return SocketAction{Kind: SocketActionAncillary, Phase: SocketPhasePastSocket, Ancillary: ancillary, Value: SocketValue{Bytes: data}}, true, nil
		}
		n, err := ancillaryOptionInt(o)
		if err != nil {
			return SocketAction{}, true, fmt.Errorf("%s: %w", name, err)
		}
		return SocketAction{Kind: SocketActionAncillary, Phase: SocketPhasePastSocket, Ancillary: ancillary, Number: n}, true, nil
	}
	return SocketAction{}, false, nil
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
		data, singleInt, err := parseDalan(parts[2], 'i')
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

func optionalNamedSocketInt(o parse.Option, named NamedSocketOption) (int, error) {
	if named == NamedSocketFIOSetown || named == NamedSocketSIOCSPGRP {
		if !o.Has {
			return 1, nil
		}
		return classicCInt(o.Value)
	}
	return optionalSocketInt(o, 1)
}

func namedSocketOption(name string) (NamedSocketOption, bool) {
	options := map[string]NamedSocketOption{
		"so-debug":         NamedSocketDebug,
		"so-dontroute":     NamedSocketDontRoute,
		"so-oobinline":     NamedSocketOOBInline,
		"so-rcvlowat":      NamedSocketRecvLowWater,
		"so-sndlowat":      NamedSocketSendLowWater,
		"so-priority":      NamedSocketPriority,
		"so-passcred":      NamedSocketPassCred,
		"so-no-check":      NamedSocketNoCheck,
		"so-detach-filter": NamedSocketDetachFilter,
		"tcp-cork":         NamedSocketTCPCork,
		"tcp-defer-accept": NamedSocketTCPDeferAccept,
		"tcp-linger2":      NamedSocketTCPLinger2,
		"tcp-maxseg":       NamedSocketTCPMaxSeg,
		"tcp-quickack":     NamedSocketTCPQuickAck,
		"tcp-syncnt":       NamedSocketTCPSyncNT,
		"tcp-window-clamp": NamedSocketTCPWindowClamp,
		"nopush":           NamedSocketTCPNoPush,
		"noopt":            NamedSocketTCPNoOpt,
		"sctp-nodelay":     NamedSocketSCTPNoDelay,
		"sctp-maxseg":      NamedSocketSCTPMaxSeg,
		"tcp-maxseg-late":  NamedSocketTCPMaxSegLate,
		"fiosetown":        NamedSocketFIOSetown,
		"siocspgrp":        NamedSocketSIOCSPGRP,
	}
	option, ok := options[name]
	return option, ok
}

func ancillaryOption(name string) (AncillaryOption, bool) {
	options := map[string]AncillaryOption{
		"so-timestamp":      AncillaryTimestamp,
		"ip-pktinfo":        AncillaryIPv4PacketInfo,
		"ip-recvttl":        AncillaryIPv4RecvTTL,
		"ip-recvtos":        AncillaryIPv4RecvTOS,
		"ip-recvopts":       AncillaryIPv4RecvOptions,
		"ip-retopts":        AncillaryIPv4RetOptions,
		"ip-recvdstaddr":    AncillaryIPv4RecvDstAddr,
		"ip-recvif":         AncillaryIPv4RecvInterface,
		"ipv6-recvpktinfo":  AncillaryIPv6PacketInfo,
		"ipv6-recvhoplimit": AncillaryIPv6RecvHopLimit,
		"ipv6-recvtclass":   AncillaryIPv6RecvTrafficClass,
		"ipv6-recvdstopts":  AncillaryIPv6RecvDstOptions,
		"ipv6-recvhopopts":  AncillaryIPv6RecvHopOptions,
		"ipv6-recvrthdr":    AncillaryIPv6RecvRoutingHeader,
		"ipv6-recvpathmtu":  AncillaryIPv6RecvPathMTU,
		"ip-ttl":            AncillaryIPv4TTL,
		"ip-tos":            AncillaryIPv4TOS,
		"ip-options":        AncillaryIPv4Options,
		"ip-hdrincl":        AncillaryIPv4HeaderIncluded,
		"ipv6-unicast-hops": AncillaryIPv6UnicastHops,
		"ipv6-tclass":       AncillaryIPv6TrafficClass,
	}
	option, ok := options[name]
	return option, ok
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

func decodeSourceMulticastRequest(o parse.Option, ipv6 bool, name string) (SourceMulticastRequest, error) {
	value, err := requiredString(o)
	if err != nil {
		return SourceMulticastRequest{}, err
	}
	parts, err := splitMulticastFields(value)
	if err != nil || len(parts) != 3 {
		return SourceMulticastRequest{}, fmt.Errorf("%s: expected group:source:interface, got %q", name, value)
	}
	return SourceMulticastRequest{
		IPv6:      ipv6,
		Name:      name,
		Group:     targetFromText(parts[0]),
		Source:    targetFromText(parts[1]),
		Interface: targetFromText(parts[2]),
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

func parseDalan(value string, defaultType byte) ([]byte, bool, error) {
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
