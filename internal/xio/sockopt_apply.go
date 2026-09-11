package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/optionmeta"
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
		addrconfig.SocketActionSourceMulticast, addrconfig.SocketActionFreebind,
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
		if name == "rcvbuf" || name == "rcvbuf-late" {
			opt = soRcvbuf
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
		return applySocketTimeoDuration(fd, action.Text, action.Duration)
	case addrconfig.SocketActionFreebind:
		return applyFreebindValue(fd, action.Number)
	case addrconfig.SocketActionTransparent:
		return applyTransparentValue(fd, action.Number)
	case addrconfig.SocketActionMTUDiscovery:
		return applyPreparedMTUDiscovery(fd, action)
	case addrconfig.SocketActionRecvErr:
		return applyPreparedRecvErr(fd, action)
	case addrconfig.SocketActionRouterAlert:
		return applyRouterAlertValue(fd, action.Number, action.Text)
	case addrconfig.SocketActionMulticast:
		return applyPreparedMulticast(fd, action.Multicast)
	case addrconfig.SocketActionSourceMulticast:
		return applyPreparedSourceMulticast(fd, action.Source)
	case addrconfig.SocketActionAncillary:
		return applyPreparedAncillary(fd, action, family, familyResolved)
	case addrconfig.SocketActionGetOnly:
		return applyPreparedGetOnly(action)
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
	name := namedSocketOptionName(action.Named)
	if name == "" {
		return nil
	}
	if action.Named == addrconfig.NamedSocketFIOSetown || action.Named == addrconfig.NamedSocketSIOCSPGRP {
		if err := applyOwnerIoctlPlatform(fd, name, action.Number); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	var level, opt int
	var ok bool
	var err error
	if action.Named == addrconfig.NamedSocketTCPMaxSegLate {
		level, opt, ok, err = lookupNamedConnectedInt(name)
	} else {
		level, opt, ok, err = lookupNamedPastSocketInt(name)
	}
	if !ok {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := setSockoptInt(fd, level, opt, action.Number); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func applyPreparedMTUDiscovery(fd int, action addrconfig.SocketAction) error {
	family := membershipFamilyIPv4
	if action.Text == "ipv6-mtu-discover" {
		family = membershipFamilyIPv6
	}
	return applyMTUDiscoveryValue(fd, family, action.Text, action.Number)
}

func applyPreparedRecvErr(fd int, action addrconfig.SocketAction) error {
	if action.Text == "ipv6-recverr" {
		return fmt.Errorf("%s: not supported (no MSG_ERRQUEUE ReadMsg path)", action.Text)
	}
	return applyRecvErrValue(fd, action.Number)
}

func applyPreparedGetOnly(action addrconfig.SocketAction) error {
	spelling := action.Text
	if spelling == "" {
		spelling = "ip-mtu"
	}
	kernel := spelling
	if def, ok := optionmeta.Lookup(spelling); ok && def.Kernel != "" {
		kernel = def.Kernel
	}
	return fmt.Errorf("%s: %s is get-only; not implemented as a setter", spelling, kernel)
}
