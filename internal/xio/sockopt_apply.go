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
		if err := setSockoptInt(fd, solSocket, soBroadcast, action.Number); err != nil {
			return fmt.Errorf("broadcast: %w", err)
		}
		return nil
	case addrconfig.SocketActionBuffer:
		opt := soSndbuf
		name := action.Text
		if action.Recv {
			opt = soRcvbuf
		}
		if name == "" {
			if action.Recv {
				name = "rcvbuf"
			} else {
				name = "sndbuf"
			}
		}
		if err := setSockoptInt(fd, solSocket, opt, action.Number); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
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

func applyPreparedGenericAction(fd int, action addrconfig.SocketAction) error {
	if action.Value.IsInt {
		if err := setSockoptInt(fd, action.Number, action.Option, action.Value.Int); err != nil {
			return fmt.Errorf("setsockopt: %w", err)
		}
		return nil
	}
	if err := setSockoptBytes(fd, action.Number, action.Option, action.Value.Bytes); err != nil {
		return fmt.Errorf("setsockopt: %w", err)
	}
	return nil
}

func applyPreparedNamedAction(fd int, action addrconfig.SocketAction) error {
	name := action.Text
	if action.Named == addrconfig.NamedSocketNone {
		return nil
	}
	if action.Named == addrconfig.NamedSocketFIOSETOWN || action.Named == addrconfig.NamedSocketSIOCSPGRP {
		if name == "" {
			if action.Named == addrconfig.NamedSocketFIOSETOWN {
				name = "fiosetown"
			} else {
				name = "siocspgrp"
			}
		}
		if err := applyOwnerIoctlPlatform(fd, action.Named, action.Number); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	var level, opt int
	var ok bool
	var err error
	if action.Named == addrconfig.NamedSocketTCPMaxSegLate {
		level, opt, ok, err = lookupNamedConnectedInt(action.Named)
	} else {
		level, opt, ok, err = lookupNamedPastSocketInt(action.Named)
	}
	if !ok {
		return nil
	}
	if name == "" {
		name = "named-socket-option"
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := setSockoptInt(fd, level, opt, action.Number); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
