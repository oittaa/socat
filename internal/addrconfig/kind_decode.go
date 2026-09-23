package addrconfig

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

// applyOption decodes one option through its catalog kind and stores the result.
// The value text is parsed only inside that kind.
func applyOption(d *decoder, o parse.Option, definition optionmeta.Option) error {
	d.optionIndex++
	if definition.Isolation {
		spelling := o.OriginalSpelling()
		if spelling == "" {
			spelling = o.Name
		}
		return fmt.Errorf("option %q is not supported (%s)", spelling, optionmeta.IsolationUnsupportedReason)
	}
	if definition.PublicTLS || (definition.Hidden && definition.TLSRejectReason != "") {
		recordTLSPlaintextName(&d.Address, o, definition)
	}
	kind := definition.Kind
	if kind == optionmeta.KindNone {
		kind = TermiosValueKind(definition.Canonical)
	}
	if definition.TLSRejectReason != "" {
		return decodeRejectedTLS(d, o, definition)
	}
	return applyKind(d, o, definition, kind)
}

func applyKind(d *decoder, o parse.Option, definition optionmeta.Option, kind optionmeta.Kind) error {
	a := &d.Address
	name := definition.Canonical
	switch kind {
	case optionmeta.KindBool:
		v, err := parseBool(o)
		if err != nil {
			return err
		}
		return assignBool(d, o, name, v)
	case optionmeta.KindNoValueName:
		return applyNoValue(d, o, name)
	case optionmeta.KindNoValueSpell:
		return applyNoValue(d, o, name)
	case optionmeta.KindString:
		if (name == "lockfile" || name == "waitlock") && a.File.LockSet {
			return fmt.Errorf("only one use of options lockfile and waitlock allowed")
		}
		value, err := requiredString(o)
		if err != nil {
			return err
		}
		return assignRequiredString(a, o, name, value)
	case optionmeta.KindPresent:
		value, err := presentString(o)
		if err != nil {
			return err
		}
		return assignPresentString(a, name, value)
	case optionmeta.KindOptionalString:
		return assignOptionalString(a, o, name)
	case optionmeta.KindInt:
		return assignInt(a, o, name, definition.Min)
	case optionmeta.KindChildrenShutup:
		return assignChildrenShutup(a, o)
	case optionmeta.KindOmittedInt:
		n, err := signedOptionalInt(o)
		if err != nil {
			return err
		}
		a.Process.SetPGID = OptionalInt{Set: true, Value: n}
		return nil
	case optionmeta.KindSeek:
		return assignSeek(a, o, name)
	case optionmeta.KindNonNeg:
		n, err := nonnegativeInt64(o)
		if err != nil {
			return err
		}
		appendFile(a, o, FileAction{Kind: FileActionTruncate, Offset: n})
		return nil
	case optionmeta.KindSize:
		n, err := sizeT(o)
		if err != nil {
			return err
		}
		a.Transfer.ReadBytes = OptionalUint64{Set: true, Value: n}
		return nil
	case optionmeta.KindDuration:
		return assignDuration(d, o, name)
	case optionmeta.KindPositiveDuration:
		return assignPositiveDuration(a, o, name)
	case optionmeta.KindSitout:
		return assignSitout(a, o)
	case optionmeta.KindMode:
		return assignMode(a, o, name, definition.Max)
	case optionmeta.KindPort:
		return assignPort(a, o, name)
	case optionmeta.KindPresentPort:
		return assignPresentPort(a, o)
	case optionmeta.KindEscape:
		b, err := escapeByte(o)
		if err != nil {
			return err
		}
		a.Transfer.Escape = OptionalByte{Set: true, Value: b}
		return nil
	case optionmeta.KindFlagInt:
		return assignFlagInt(a, o, name)
	case optionmeta.KindReuseAddr:
		return assignReuseAddr(a, o)
	case optionmeta.KindSocketInt:
		return assignSocketInt(a, o, name)
	case optionmeta.KindProtocol:
		return assignProtocol(a, o)
	case optionmeta.KindBacklog:
		backlog, err := decodePositiveInt(o)
		if err != nil {
			return optionValueError(o, "invalid value", strconv.Quote(o.Value))
		}
		a.Network.Backlog = OptionalInt{Set: true, Value: backlog}
		return nil
	case optionmeta.KindKeepCnt:
		count, err := decodePositiveInt(o)
		if err != nil {
			return optionValueError(o, "invalid value", strconv.Quote(o.Value))
		}
		a.Network.KeepCnt = OptionalInt{Set: true, Value: count}
		return nil
	case optionmeta.KindOwner:
		return assignOwner(a, o, name)
	case optionmeta.KindFamily:
		return assignFamily(a, o)
	case optionmeta.KindRange:
		return assignRange(a, o)
	case optionmeta.KindBind:
		return applyBind(a, o)
	case optionmeta.KindShut:
		return decodeShutdown(&a.Transfer.Shutdown, o)
	case optionmeta.KindNamedShut:
		return decodeNamedShutdown(&a.Transfer.Shutdown, o, shutdownMode(name))
	case optionmeta.KindFD:
		return assignFD(a, o, name)
	case optionmeta.KindResNS:
		return assignResNS(a, o)
	case optionmeta.KindHTTPVersion:
		return assignHTTPVersion(a, o)
	case optionmeta.KindCiphers:
		return assignCiphers(a, o)
	case optionmeta.KindALPN:
		return assignALPN(a, o)
	case optionmeta.KindProtoMin:
		return decodeProtocolVersion(a, o, true)
	case optionmeta.KindProtoMax:
		return decodeProtocolVersion(a, o, false)
	case optionmeta.KindDTLSMTU:
		return assignDTLSMTU(a, o)
	case optionmeta.KindTUNType:
		return assignTUNType(a, o)
	case optionmeta.KindTUNMTU:
		return assignTUNMTU(a, o)
	case optionmeta.KindMQPrio:
		return assignMQPrio(a, o)
	case optionmeta.KindLink:
		value, err := requiredString(o)
		if err != nil {
			return err
		}
		a.Terminal.Link = OptionalString{Set: true, Value: value}
		return nil
	case optionmeta.KindIoctl:
		action, err := decodeIoctl(o, name)
		if err != nil {
			return err
		}
		a.File.Actions = append(a.File.Actions, action)
		return nil
	case optionmeta.KindWinSize:
		col, row, err := terminalWinSize(o)
		if err != nil {
			return err
		}
		appendTerminal(a, TerminalAction{Kind: TerminalActionWinSize, Name: name, Col: col, Row: row})
		return nil
	case optionmeta.KindTermiosByte:
		value, err := terminalByte(o)
		if err != nil {
			return err
		}
		appendTerminal(a, TerminalAction{Kind: TerminalActionChar, Name: name, Value: uint32(value)})
		return nil
	case optionmeta.KindTermiosUint:
		value, err := terminalUint(o)
		if err != nil {
			return err
		}
		appendTerminal(a, TerminalAction{Kind: TerminalActionSpeed, Name: name, Value: value})
		return nil
	case optionmeta.KindTermiosField:
		value, err := terminalUint(o)
		if err != nil {
			return err
		}
		if value > 3 {
			return optionValueError(o, "invalid value", strconv.Quote(o.Value))
		}
		appendTerminal(a, TerminalAction{Kind: TerminalActionField, Name: name, Value: value})
		return nil
	case optionmeta.KindTermiosFlags:
		word, flags, err := terminalSetFlags(o)
		if err != nil {
			return err
		}
		appendTerminal(a, TerminalAction{Kind: TerminalActionSetFlags, Name: name, Word: word, Flags: flags})
		return nil
	case optionmeta.KindSockoptDalan, optionmeta.KindSockoptInt, optionmeta.KindSockoptString,
		optionmeta.KindWordInt, optionmeta.KindBuffer, optionmeta.KindLinger, optionmeta.KindTimeout,
		optionmeta.KindBindDevice, optionmeta.KindNamedWord, optionmeta.KindNamedInt, optionmeta.KindNamedCInt,
		optionmeta.KindAncillary, optionmeta.KindIPOptions, optionmeta.KindRecvErr, optionmeta.KindMTUDiscover,
		optionmeta.KindRouterAlert, optionmeta.KindTransparent, optionmeta.KindGetOnly,
		optionmeta.KindMcastJoin4, optionmeta.KindMcastJoin6, optionmeta.KindMcastIf, optionmeta.KindMcastLoop4,
		optionmeta.KindMcastTTL, optionmeta.KindMcastLoop6, optionmeta.KindMcastSource4, optionmeta.KindMcastSource6:
		action, err := socketAction(kind, o, name, definition.Kernel)
		if err != nil || action.Kind == 0 {
			return err
		}
		appendSocket(a, action)
		return nil
	default:
		return nil
	}
}

func decodeRejectedTLS(d *decoder, o parse.Option, definition optionmeta.Option) error {
	name := definition.Canonical
	reject := true
	switch definition.Kind {
	case optionmeta.KindHiddenString:
		if _, err := requiredString(o); err != nil {
			return err
		}
	case optionmeta.KindHiddenCompress:
		text, err := requiredString(o)
		if err != nil {
			return err
		}
		reject = !strings.EqualFold(strings.TrimSpace(text), "none")
	case optionmeta.KindHiddenBool:
		v, err := parseBool(o)
		if err != nil {
			return err
		}
		reject = v.Value
	case optionmeta.KindHiddenInt:
		if o.Has {
			if _, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64); err != nil {
				return optionValueError(o, "invalid value", strconv.Quote(o.Value))
			}
		}
	default:
	}
	recordUnsupportedTLS(d, name, o, definition.TLSRejectReason, reject)
	return nil
}

func appendFile(a *Address, o parse.Option, action FileAction) {
	action.Name = o.OriginalSpelling()
	a.File.Actions = append(a.File.Actions, action)
}

func appendTerminal(a *Address, action TerminalAction) {
	a.Terminal.Actions = append(a.Terminal.Actions, action)
}

func appendSocket(a *Address, action SocketAction) {
	a.Network.Actions = append(a.Network.Actions, action)
	if action.Kind != SocketActionTimeout {
		return
	}
	opt := OptionalDuration{Set: true, Value: action.Duration}
	if action.Recv {
		a.Common.ReadTimeout = opt
		return
	}
	a.Common.WriteTimeout = opt
}

func assignBool(d *decoder, o parse.Option, name string, v OptionalBool) error {
	a := &d.Address
	if terminalFlagName(name) {
		appendTerminal(a, TerminalAction{Kind: TerminalActionFlag, Name: name, Enabled: v.Value})
		return nil
	}
	if bit, ok := interfaceFlagBit(name); ok {
		if v.Value {
			a.Network.TUNInterfaceSet |= bit
			a.Network.TUNInterfaceClr &^= bit
		} else {
			a.Network.TUNInterfaceClr |= bit
			a.Network.TUNInterfaceSet &^= bit
		}
		return nil
	}
	switch name {
	case "rdonly", "wronly", "rdwr":
		if v.Value {
			switch name {
			case "rdonly":
				a.File.Access = FileAccessRead
			case "wronly":
				a.File.Access = FileAccessWrite
			default:
				a.File.Access = FileAccessReadWrite
			}
		}
	case "creat":
		a.File.Create = v
	case "excl":
		a.File.Exclusive = v.Value
	case "append":
		a.File.AppendSet = true
		a.File.Append = v.Value
		appendFile(a, o, FileAction{Kind: FileActionAppend, Enabled: v.Value})
	case "trunc":
		a.File.Truncate = v.Value
	case "nonblock":
		a.File.Nonblock = v.Value
	case "o-direct", "o-sync", "o-dsync", "o-rsync", "o-noctty", "o-nofollow", "o-directory", "o-largefile":
		appendFile(a, o, FileAction{Kind: FileActionOpenFlag, Flag: openFlagID(name), Enabled: v.Value})
	case "async":
		appendFile(a, o, FileAction{Kind: FileActionAsync, Flag: OpenFlagAsync, Enabled: v.Value})
	case "flock", "flock-nb", "flock-sh", "flock-sh-nb", "setlk", "setlkw", "setlk-rd", "setlkw-rd":
		appendFile(a, o, FileAction{Kind: flockKind(name), Enabled: v.Value, Value: flockValue(name)})
	case "cloexec":
		appendFile(a, o, FileAction{Kind: FileActionCloexec, Enabled: v.Value})
	case "noinherit":
		appendFile(a, o, FileAction{Kind: FileActionNoInherit, Enabled: v.Value})
	case "o-noatime":
		appendFile(a, o, FileAction{Kind: FileActionNoAtime, Enabled: v.Value})
	case "fs-secrm", "fs-unrm", "fs-compr", "fs-sync", "fs-immutable", "fs-append", "fs-nodump", "fs-noatime", "fs-journal-data", "fs-notail", "fs-dirsync", "fs-topdir":
		appendFile(a, o, FileAction{Kind: FileActionFSFlag, Enabled: v.Value, FS: fsFlagID(name)})
	case "unlink":
		appendFile(a, o, FileAction{Kind: FileActionUnlink, Enabled: v.Value})
	case "unlink-early":
		a.File.UnlinkEarly = v
	case "unlink-late":
		a.File.UnlinkLate = v
	case "unlink-close":
		a.File.UnlinkClose = v
	case "pipes":
		a.Process.Pipes = v
	case "stderr":
		a.Process.Stderr = v
	case "setsid":
		a.Process.SetSID = v
	case "dash":
		a.Process.Dash = v
	case "pty", "ptmx", "openpty":
		a.Process.PTY = v
	case "fork":
		a.Common.Fork = v
	case "nofork":
		a.Common.NoFork = v
	case "forever":
		a.Common.Retry.Forever = v
	case "ignoreeof":
		a.Transfer.IgnoreEOF = v
	case "null-eof":
		a.Transfer.NullEOF = v
	case "end-close":
		a.Transfer.EndClose = v
	case "crorlf":
		d.crorlf = lineConversion{set: true, active: v.Value, index: d.optionIndex, ending: LineEndingCROrLF}
	case "binary":
		a.Common.Binary = v
	case "text":
		a.Common.Text = v
	case "res-usevc":
		a.Common.UseVC = v
	case "ai-addrconfig":
		a.Common.AddrConfig = v
	case "ai-passive":
		a.Common.Passive = v
	case "ai-v4mapped":
		a.Common.V4Mapped = v
	case "ai-all":
		a.Common.AddrInfoAll = v
	case "lowport":
		a.Network.LowPort = v
	case "ipv6-v6only":
		a.Common.IPv6V6Only = v
	case "unix-tightsocklen":
		a.Network.UnixTightSocklen = v
	case "verify":
		a.TLS.Verify = v
	case "nosni":
		a.TLS.NoSNI = v
	case "dtls-migration":
		a.TLS.DTLSMigration = v
	case "dtls-unfragmented-probes":
		a.TLS.DTLSUnfragmentedProbes = v
	case "h2c":
		a.Proxy.H2C = v
	case "ignorecr":
		a.Proxy.IgnoreCR = v
	case "proxy-resolve":
		a.Proxy.Resolve = v
	case "pty-wait-slave":
		a.Terminal.WaitSlave = v
	case "ctty":
		a.Terminal.CTTY = v
		a.Process.CTTY = v
	case "iff-no-pi":
		a.Network.TUNNoPacketInfo = v
	case "mq-flush":
		a.Network.MQFlush = v
	}
	return nil
}

func flockKind(name string) FileActionKind {
	switch name {
	case "setlk", "setlkw", "setlk-rd", "setlkw-rd":
		return FileActionLock
	default:
		return FileActionFlock
	}
}

func flockValue(name string) int {
	switch name {
	case "flock-nb", "setlkw":
		return 2
	case "flock-sh", "setlk-rd":
		return 3
	case "flock-sh-nb", "setlkw-rd":
		return 4
	default:
		return 1
	}
}

func applyNoValue(d *decoder, o parse.Option, name string) error {
	if o.Has {
		return optionValueError(o, "no value permitted", "")
	}
	a := &d.Address
	if terminalComboName(name) {
		appendTerminal(a, TerminalAction{Kind: TerminalActionCombo, Name: name})
		return nil
	}
	if baud, ok := terminalBaud(name); ok {
		appendTerminal(a, TerminalAction{Kind: TerminalActionSpeed, Name: name, Value: baud})
		return nil
	}
	if terminalConstantFlagName(name) {
		appendTerminal(a, TerminalAction{Kind: TerminalActionFlag, Name: name, Enabled: true})
		return nil
	}
	switch name {
	case "cr":
		d.cr = lineConversion{set: true, active: true, index: d.optionIndex, ending: LineEndingCR}
	case "crnl":
		d.crnl = lineConversion{set: true, active: true, index: d.optionIndex, ending: LineEndingCRNL}
	case "sighup":
		a.Process.ParentSignals = append(a.Process.ParentSignals, ParentSignalHUP)
	case "sigint":
		a.Process.ParentSignals = append(a.Process.ParentSignals, ParentSignalINT)
	case "sigquit":
		a.Process.ParentSignals = append(a.Process.ParentSignals, ParentSignalQUIT)
	case "retrieve-vlan":
		a.Network.TUNRetrieveVLAN = true
	}
	return nil
}

func assignRequiredString(a *Address, o parse.Option, name, value string) error {
	switch name {
	case "netns":
		a.Common.NetNamespace = OptionalString{Set: true, Value: value}
	case "chdir":
		a.Process.Chdir = OptionalString{Set: true, Value: value}
	case "lockfile", "waitlock":
		a.File.LockSet, a.File.LockWait, a.File.LockPath = true, name == "waitlock", value
	case "tcpwrap-etc":
		a.Network.TCPWrapEtc = OptionalString{Set: true, Value: value}
	case "hosts-allow":
		a.Network.HostsAllow = OptionalString{Set: true, Value: value}
	case "hosts-deny":
		a.Network.HostsDeny = OptionalString{Set: true, Value: value}
	case "tun-device":
		a.Network.TUNDevice = value
	case "tun-name":
		a.Network.TUNName = value
	}
	return nil
}

func assignPresentString(a *Address, name, value string) error {
	opt := OptionalString{Set: true, Value: value}
	switch name {
	case "shell":
		a.Process.Shell = opt
	case "cert":
		a.TLS.Certificate = opt
	case "key":
		a.TLS.Key = opt
	case "cafile":
		a.TLS.CAFile = opt
	case "capath":
		a.TLS.CAPath = opt
	case "commonname":
		a.TLS.CommonName = opt
	case "snihost":
		a.TLS.SNIHost = opt
	case "origin":
		a.TLS.WSOrigin = opt
	case "path":
		a.TLS.WSPath = opt
	case "proxy-authorization":
		a.Proxy.Authorization = opt
	case "proxy-authorization-file":
		a.Proxy.AuthorizationFile = opt
	case "socksuser":
		a.Proxy.SOCKSUser = opt
	case "sockspass":
		a.Proxy.SOCKSPassword = opt
	}
	return nil
}

func assignOptionalString(a *Address, o parse.Option, name string) error {
	opt := OptionalString{Set: true, Value: o.Value}
	if !o.Has {
		opt = omittedString()
	}
	switch name {
	case "tcpwrap":
		a.Network.TCPWrap = OptionalBool{Set: true, Value: true}
		a.Network.TCPWrapDaemon = opt
	case "unix-bind-tempname":
		a.Network.UnixBindTempname = opt
	}
	return nil
}

func assignInt(a *Address, o parse.Option, name string, min int) error {
	n, err := requiredInt(o, min)
	if err != nil {
		return err
	}
	opt := OptionalInt{Set: true, Value: n}
	switch name {
	case "max-children":
		a.Common.MaxChildren = opt
	case "retry":
		a.Common.Retry.Count = opt
	case "f-setpipe-sz":
		appendFile(a, o, FileAction{Kind: FileActionPipeSize, Value: n})
	case "mq-maxmsg":
		a.Network.MQMaxMessages = opt
	case "mq-msgsize":
		a.Network.MQMessageSize = opt
	}
	return nil
}

func assignChildrenShutup(a *Address, o parse.Option) error {
	if !o.Has {
		a.Common.ChildrenShutup = OptionalInt{Set: true, Value: 1}
		return nil
	}
	n, err := requiredInt(o, 0)
	if err != nil {
		return err
	}
	a.Common.ChildrenShutup = OptionalInt{Set: true, Value: n}
	return nil
}

func assignSeek(a *Address, o parse.Option, name string) error {
	n, err := seekOffset(o)
	if err != nil {
		return err
	}
	kind := FileActionSeekStart
	switch name {
	case "seek-cur":
		kind = FileActionSeekCurrent
	case "seek-end":
		kind = FileActionSeekEnd
	}
	appendFile(a, o, FileAction{Kind: kind, Offset: n})
	return nil
}

func assignDuration(d *decoder, o parse.Option, name string) error {
	value, err := duration(o)
	if err != nil {
		return err
	}
	a := &d.Address
	opt := OptionalDuration{Set: true, Value: value}
	switch name {
	case "interval":
		a.Common.Retry.Interval = value
	case "connect-timeout":
		a.Common.ConnectTimeout = opt
	case "handshake-timeout":
		a.Common.HandshakeTimeout = opt
	case "accept-timeout":
		a.Common.AcceptTimeout = opt
	case "pty-interval":
		a.Terminal.WaitInterval = opt
	}
	return nil
}

func assignPositiveDuration(a *Address, o parse.Option, name string) error {
	var dst *OptionalDuration
	switch name {
	case "keepintvl":
		dst = &a.Network.KeepIntvl
	default:
		dst = &a.Network.KeepIdle
	}
	return decodePositiveDuration(dst, o)
}

func assignSitout(a *Address, o parse.Option) error {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return optionValueError(o, "requires a value", "")
	}
	value, err := ParseDuration(o.Value)
	if err != nil || value < 0 {
		return optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	a.Terminal.SitoutEIO = OptionalDuration{Set: true, Value: value}
	return nil
}

func assignMode(a *Address, o parse.Option, name string, max uint32) error {
	mode, err := fileMode(o, max)
	if err != nil {
		return err
	}
	if name == "umask" {
		a.File.Umask = OptionalUint32{Set: true, Value: mode}
		return nil
	}
	kind := FileActionPerm
	switch name {
	case "perm-late":
		kind = FileActionPermLate
	case "perm-early":
		kind = FileActionPermEarly
	}
	appendFile(a, o, FileAction{Kind: kind, Mode: mode})
	return nil
}

func assignPort(a *Address, o parse.Option, name string) error {
	port, err := requiredPortTarget(o)
	if err != nil {
		return err
	}
	if name == "proxyport" {
		a.Proxy.Port = port
		a.Proxy.PortSet = true
		return nil
	}
	a.Network.SourcePort = port
	a.Network.SourcePortSet = true
	return nil
}

func assignPresentPort(a *Address, o parse.Option) error {
	text, err := presentString(o)
	if err != nil {
		return err
	}
	port, err := portTarget(text)
	if err != nil {
		return optionValueError(o, "invalid value", err.Error())
	}
	a.Proxy.SOCKSPort = port
	a.Proxy.SOCKSPortSet = true
	return nil
}

func assignFlagInt(a *Address, o parse.Option, name string) error {
	switch name {
	case "reuseport":
		return setFlagInt(&a.Network.ReusePort, o)
	case "keepalive":
		return setFlagInt(&a.Network.KeepAlive, o)
	default:
		return setFlagInt(&a.Network.NoDelay, o)
	}
}

func assignReuseAddr(a *Address, o parse.Option) error {
	if o.Has && o.Value == "" {
		a.Network.ReuseAddr = OptionalBool{Set: true, Value: false}
		return nil
	}
	return setActive(&a.Network.ReuseAddr, o)
}

func assignSocketInt(a *Address, o parse.Option, name string) error {
	value, err := requiredSocketInt(o)
	if err != nil {
		return err
	}
	opt := OptionalInt{Set: true, Value: value}
	if name == "socktype" {
		a.Network.SocketType = opt
		return nil
	}
	a.Network.SocketProtocol = opt
	return nil
}

func assignProtocol(a *Address, o parse.Option) error {
	if a.Network.Kind == AddressKindSocket || a.Network.Kind == AddressKindVSOCK {
		value, err := requiredSocketInt(o)
		if err != nil {
			return err
		}
		a.Network.SocketProtocol = OptionalInt{Set: true, Value: value}
		return nil
	}
	return setRequiredString(&a.TLS.WSProtocol, o)
}

func assignOwner(a *Address, o parse.Option, name string) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	owner, err := parseOwnerRef(value)
	if err != nil {
		return optionValueError(o, "invalid value", strconv.Quote(value))
	}
	kind := FileActionUser
	switch name {
	case "group":
		kind = FileActionGroup
	case "user-late":
		kind = FileActionUserLate
	case "group-late":
		kind = FileActionGroupLate
	case "user-early":
		kind = FileActionUserEarly
	case "group-early":
		kind = FileActionGroupEarly
	}
	appendFile(a, o, FileAction{Kind: kind, Owner: owner})
	return nil
}

func assignFamily(a *Address, o parse.Option) error {
	text, err := requiredString(o)
	if err != nil {
		return err
	}
	pf, family, err := protocolFamily(text)
	if err != nil {
		return optionValueError(o, "invalid value", err.Error())
	}
	a.Network.ProtocolFamily, a.Network.ProtocolSet, a.Network.IPFamily = pf, true, family
	return nil
}

func assignRange(a *Address, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	parsed, err := ParseIPRange(value)
	if err != nil {
		return optionValueError(o, "invalid value", strconv.Quote(value))
	}
	a.Network.Range, a.Network.RangeSet = parsed, true
	return nil
}

func applyBind(a *Address, o parse.Option) error {
	n := &a.Network
	text, err := presentString(o)
	if err != nil {
		return err
	}
	if n.Kind == AddressKindSocket {
		data, err := ParseSocatData(text)
		if err != nil {
			return optionValueError(o, "invalid value", err.Error())
		}
		n.RawBind, n.RawBindSet = data, true
		return nil
	}
	if n.Kind == AddressKindVSOCK {
		ep, hasPort, err := decodeVSOCKBind(text)
		if err != nil {
			return optionValueError(o, "invalid value", strconv.Quote(text))
		}
		n.VSOCKBind, n.VSOCKBindSet, n.VSOCKBindHasPort = ep, true, hasPort
		n.BindSet = true
		return nil
	}
	if filesystemBindKind(n.Kind) {
		n.Bind = HostTarget{Name: text}
		n.BindSet = true
		return nil
	}
	bind, bindPort, bindPortSet, err := parseBindValue(text, bindSplitsHostPort(n))
	if err != nil {
		return optionValueError(o, "invalid value", err.Error())
	}
	n.Bind, n.BindPort, n.BindPortSet = bind, bindPort, bindPortSet
	n.BindSet = true
	return nil
}

func shutdownMode(name string) ShutdownMode {
	switch name {
	case "shut-down":
		return ShutdownDown
	case "shut-close":
		return ShutdownClose
	case "shut-null":
		return ShutdownNull
	default:
		return ShutdownNone
	}
}

func assignFD(a *Address, o parse.Option, name string) error {
	n, set, err := processFD(o)
	if err != nil {
		return err
	}
	fd := OptionalInt{Set: set, Value: n}
	if name == "fdin" {
		a.Process.FDIn = fd
		return nil
	}
	a.Process.FDOut = fd
	return nil
}

func assignResNS(a *Address, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	ns, err := ParseResNSAddr(value)
	if err != nil {
		return optionValueError(o, "invalid value", strings.TrimPrefix(err.Error(), "res-nsaddr: "))
	}
	a.Common.NameServer = ns
	return nil
}

func assignHTTPVersion(a *Address, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	version, err := decodeHTTPVersion(value)
	if err != nil {
		return optionValueError(o, "invalid value", strconv.Quote(value))
	}
	a.Proxy.HTTPVersion = version
	return nil
}

func assignCiphers(a *Address, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		a.TLS.CipherSuites = nil
		return nil
	}
	suites, err := decodeCipherSuites(value)
	if err != nil {
		return optionValueError(o, "invalid value", strings.TrimPrefix(err.Error(), "ciphers: "))
	}
	a.TLS.CipherSuites = suites
	return nil
}

func assignALPN(a *Address, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	if len(value) > 255 {
		return optionValueError(o, "invalid value", "protocol must contain 1 to 255 bytes")
	}
	a.TLS.ALPN = OptionalString{Set: true, Value: value}
	return nil
}

func assignDTLSMTU(a *Address, o parse.Option) error {
	value, err := requiredInt(o, 256)
	if err != nil || value > 65507 {
		if !o.Has || strings.TrimSpace(o.Value) == "" {
			return optionValueError(o, "requires a value", "")
		}
		return optionValueError(o, "invalid value", "must be between 256 and 65507")
	}
	a.TLS.DTLSMTU = OptionalInt{Set: true, Value: value}
	return nil
}

func assignTUNType(a *Address, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	switch strings.ToLower(value) {
	case "tun":
		a.Network.TUNType = TUNTypeTUN
	case "tap":
		a.Network.TUNType = TUNTypeTAP
	default:
		return optionValueError(o, "invalid value", strconv.Quote(value))
	}
	return nil
}

func assignTUNMTU(a *Address, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	mtu, err := strconv.ParseUint(value, 0, 32)
	if err != nil || mtu == 0 {
		return optionValueError(o, "invalid value", strconv.Quote(value))
	}
	a.Network.TUNMTU = OptionalUint32{Set: true, Value: uint32(mtu)}
	return nil
}

func assignMQPrio(a *Address, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	v, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return optionValueError(o, "invalid value", strconv.Quote(value))
	}
	a.Network.MQPriority = OptionalUint32{Set: true, Value: uint32(v)}
	return nil
}
