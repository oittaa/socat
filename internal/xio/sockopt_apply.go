package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
)

type socketApplyPass uint8

const (
	socketApplyPastSocket socketApplyPass = iota
	socketApplyPrebind
	socketApplyConnected
	socketApplySocketpair
)

func applyPreparedSocketPhase(fd int, config addrconfig.Address, pass socketApplyPass, network string) error {
	family := ipFamilyFromNetwork(network)
	familyResolved := family != ipFamilyUnknown
	applyIP := ipSendAppliesToNetwork(network)
	for _, action := range config.Network.Actions {
		if !socketActionMatchesPass(action, pass) {
			continue
		}
		if pass == socketApplyPastSocket && !applyIP && socketActionIsIP(action) {
			continue
		}
		if err := applyPreparedSocketAction(fd, action, &family, &familyResolved); err != nil {
			return err
		}
	}
	return nil
}

func socketActionMatchesPass(action addrconfig.SocketAction, pass socketApplyPass) bool {
	switch pass {
	case socketApplyPastSocket:
		if action.Kind == addrconfig.SocketActionFreebind {
			return true
		}
		if action.Kind == addrconfig.SocketActionBuffer && action.Phase == addrconfig.SocketPhaseLate {
			return false
		}
		return action.Phase == addrconfig.SocketPhasePastSocket
	case socketApplyPrebind:
		return action.Phase == addrconfig.SocketPhasePrebind && action.Kind != addrconfig.SocketActionFreebind
	case socketApplyConnected:
		return action.Phase == addrconfig.SocketPhaseConnected
	case socketApplySocketpair:
		if action.Phase == addrconfig.SocketPhaseLate {
			return false
		}
		switch action.Kind {
		case addrconfig.SocketActionGeneric, addrconfig.SocketActionNamed,
			addrconfig.SocketActionBroadcast, addrconfig.SocketActionBuffer,
			addrconfig.SocketActionBindToDevice, addrconfig.SocketActionLinger,
			addrconfig.SocketActionTimeout:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func socketActionIsIP(action addrconfig.SocketAction) bool {
	switch action.Kind {
	case addrconfig.SocketActionAncillary, addrconfig.SocketActionMulticast,
		addrconfig.SocketActionFreebind,
		addrconfig.SocketActionMTUDiscovery, addrconfig.SocketActionRecvErr,
		addrconfig.SocketActionRouterAlert, addrconfig.SocketActionGetOnly:
		return true
	default:
		return false
	}
}

func applyPreparedSocketAction(fd int, action addrconfig.SocketAction, family *ipFamily, familyResolved *bool) error {
	switch action.Kind {
	case addrconfig.SocketActionGeneric:
		return applyPreparedGenericAction(fd, action)
	case addrconfig.SocketActionNamed:
		return applyPreparedNamedAction(fd, action)
	case addrconfig.SocketActionBroadcast:
		return sockerr("broadcast", setSockoptInt(fd, solSocket, soBroadcast, action.Number))
	case addrconfig.SocketActionBuffer:
		opt, name := soSndbuf, action.Text
		if action.Recv {
			opt = soRcvbuf
			if name == "" {
				name = "rcvbuf"
			}
		} else if name == "" {
			name = "sndbuf"
		}
		return sockerr(name, setSockoptInt(fd, solSocket, opt, action.Number))
	case addrconfig.SocketActionBindToDevice:
		return applyBindToDeviceName(fd, action.Text)
	case addrconfig.SocketActionLinger:
		return applyLingerSeconds(fd, action.Number)
	case addrconfig.SocketActionTimeout:
		return applySocketTimeoDuration(fd, action)
	case addrconfig.SocketActionFreebind:
		return applyFreebindValue(fd, action.Number)
	case addrconfig.SocketActionTransparent:
		return applyTransparentValue(fd, action.Number)
	case addrconfig.SocketActionMTUDiscovery:
		family := membershipFamilyIPv4
		if action.IPv6 {
			family = membershipFamilyIPv6
		}
		return applyMTUDiscoveryValue(fd, family, action.Text, action.Number)
	case addrconfig.SocketActionRecvErr:
		if action.IPv6 {
			name := action.Text
			if name == "" {
				name = "ipv6-recverr"
			}
			return fmt.Errorf("%s: not supported (no MSG_ERRQUEUE ReadMsg path)", name)
		}
		return applyRecvErrValue(fd, action.Number)
	case addrconfig.SocketActionRouterAlert:
		return applyRouterAlertValue(fd, action.Number, action.Text)
	case addrconfig.SocketActionMulticast:
		return applyPreparedMulticast(fd, action.Multicast)
	case addrconfig.SocketActionAncillary:
		return applyPreparedAncillary(fd, action, family, familyResolved)
	case addrconfig.SocketActionGetOnly:
		spelling, kernel := getOnlyNames(action)
		return fmt.Errorf("%s: %s is get-only; not implemented as a setter", spelling, kernel)
	default:
		return nil
	}
}

func sockerr(name string, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func applyPreparedGenericAction(fd int, action addrconfig.SocketAction) error {
	var err error
	if action.Value.IsInt {
		err = setSockoptInt(fd, action.Number, action.Option, action.Value.Int)
	} else {
		err = setSockoptBytes(fd, action.Number, action.Option, append([]byte(nil), action.Value.Bytes...))
	}
	return sockerr("setsockopt", err)
}

func applyPreparedNamedAction(fd int, action addrconfig.SocketAction) error {
	if action.Named == addrconfig.NamedSocketNone {
		return nil
	}
	name := action.Text
	if action.Named == addrconfig.NamedSocketFIOSETOWN || action.Named == addrconfig.NamedSocketSIOCSPGRP {
		if name == "" {
			name = "siocspgrp"
			if action.Named == addrconfig.NamedSocketFIOSETOWN {
				name = "fiosetown"
			}
		}
		return sockerr(name, applyOwnerIoctlPlatform(fd, action.Named, action.Number))
	}
	lookup := lookupNamedPastSocketInt
	if action.Named == addrconfig.NamedSocketTCPMaxSegLate {
		lookup = lookupNamedConnectedInt
	}
	level, opt, ok, err := lookup(action.Named)
	if !ok {
		return nil
	}
	if name == "" {
		name = "named-socket-option"
	}
	if err != nil {
		return sockerr(name, err)
	}
	return sockerr(name, setSockoptInt(fd, level, opt, action.Number))
}
