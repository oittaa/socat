package xio

import (
	"strings"
	"sync"
)

// Help section titles. RegisterAddress Group values must use these so
// defaultGroupOrder stays in sync.
const (
	GroupFiles     = "Files and stdio"
	GroupTCP       = "TCP"
	GroupUDP       = "UDP"
	GroupRawIP     = "Raw IP"
	GroupUnix      = "UNIX and abstract"
	GroupSocket    = "Generic socket"
	GroupProcess   = "Process"
	GroupTLS       = "TLS (OPENSSL/SSL aliases)"
	GroupProxy     = "PROXY and SOCKS"
	GroupTUN       = "Linux TUN / INTERFACE"
	GroupWebSocket = "WebSocket (Go extra)" // #nosec G101 -- help section title, not a secret
	GroupQUIC      = "QUIC (Go extra, not HTTP/3)"
	GroupSCTP      = "SCTP (Linux)"
	GroupPOSIXMQ   = "POSIX message queues (Linux)"
)

// HelpAddr represents a single address entry in help output.
type HelpAddr struct {
	Syntax string
	Desc   string
}

// HelpAddrGroup represents a section of address types in help output.
type HelpAddrGroup struct {
	Title string
	Addrs []HelpAddr
}

// AddressDesc describes a registered address type.
// Each help line is its own descriptor (including classic aliases such as TCP-L).
type AddressDesc struct {
	Group       string        // Section title; use Group* constants
	Name        string        // Keyword, e.g. "TCP" or "TCP-L"
	Syntax      string        // Help syntax, e.g. "TCP:<host>:<port>"
	Desc        string        // Help description
	DynamicDesc func() string // Optional dynamic help description (e.g. UNIX capabilities)
	Enabled     func() bool   // Optional feature predicate. If nil, considered enabled.
	Opener      Opener        // Opener function handling this address
}

var (
	registryMu   sync.RWMutex
	openers      = map[string]Opener{}
	addrsByGroup = map[string][]AddressDesc{}
	groupOrder   = []string{}
)

var defaultGroupOrder = []string{
	GroupFiles,
	GroupTCP,
	GroupUDP,
	GroupRawIP,
	GroupUnix,
	GroupSocket,
	GroupProcess,
	GroupTLS,
	GroupProxy,
	GroupTUN,
	GroupWebSocket,
	GroupQUIC,
	GroupSCTP,
	GroupPOSIXMQ,
}

// RegisterAddress associates an address descriptor with an opener and help line.
func RegisterAddress(desc AddressDesc) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if desc.Opener != nil && desc.Name != "" {
		openers[strings.ToUpper(desc.Name)] = desc.Opener
	}
	if desc.Group != "" && desc.Syntax != "" {
		if _, exists := addrsByGroup[desc.Group]; !exists {
			groupOrder = append(groupOrder, desc.Group)
		}
		addrsByGroup[desc.Group] = append(addrsByGroup[desc.Group], desc)
	}
}

// Register associates a classic address type name with an opener.
// It does not add a -h line; prefer RegisterAddress with Syntax set.
func Register(name string, fn Opener) {
	RegisterAddress(AddressDesc{
		Name:   name,
		Opener: fn,
	})
}

func lookupOpener(typ string) (Opener, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	fn, ok := openers[typ]
	return fn, ok
}

// DefaultHelpGroupOrder is the -h section order.
func DefaultHelpGroupOrder() []string {
	return append([]string(nil), defaultGroupOrder...)
}

// AddressRegistration is a snapshot of one registered address type.
type AddressRegistration struct {
	Name    string
	Group   string
	Syntax  string
	Enabled bool
}

// AddressRegistrations returns every opener and its help metadata.
func AddressRegistrations() []AddressRegistration {
	registryMu.RLock()
	defer registryMu.RUnlock()
	seen := map[string]bool{}
	var out []AddressRegistration
	for _, descs := range addrsByGroup {
		for _, d := range descs {
			name := strings.ToUpper(d.Name)
			seen[name] = true
			out = append(out, AddressRegistration{
				Name:    name,
				Group:   d.Group,
				Syntax:  d.Syntax,
				Enabled: d.Enabled == nil || d.Enabled(),
			})
		}
	}
	for name := range openers {
		if !seen[name] {
			out = append(out, AddressRegistration{Name: name})
		}
	}
	return out
}

// HelpAddressGroups returns address groups and entries formatted for help output.
func HelpAddressGroups() []HelpAddrGroup {
	registryMu.RLock()
	defer registryMu.RUnlock()

	seenGroups := make(map[string]bool)
	var orderedGroups []string
	for _, g := range defaultGroupOrder {
		if _, ok := addrsByGroup[g]; ok {
			orderedGroups = append(orderedGroups, g)
			seenGroups[g] = true
		}
	}
	for _, g := range groupOrder {
		if !seenGroups[g] {
			orderedGroups = append(orderedGroups, g)
			seenGroups[g] = true
		}
	}

	var res []HelpAddrGroup
	for _, g := range orderedGroups {
		var list []HelpAddr
		for _, a := range addrsByGroup[g] {
			if a.Enabled != nil && !a.Enabled() {
				continue
			}
			desc := a.Desc
			if a.DynamicDesc != nil {
				desc = a.DynamicDesc()
			}
			list = append(list, HelpAddr{
				Syntax: a.Syntax,
				Desc:   desc,
			})
		}
		if len(list) > 0 {
			res = append(res, HelpAddrGroup{
				Title: g,
				Addrs: list,
			})
		}
	}
	return res
}

// UnixGenericHelp returns the description for generic UNIX client addresses.
func UnixGenericHelp() string {
	switch {
	case FeatureUNIXSeqpacket:
		return "generic UNIX client; auto-detects stream, seqpacket, or datagram"
	case FeatureUNIXDatagram:
		return "generic UNIX client; auto-detects stream or datagram"
	default:
		return "UNIX stream client"
	}
}

// UnixConnectHelp returns the description for UNIX-CONNECT addresses.
func UnixConnectHelp() string {
	switch {
	case FeatureUNIXSeqpacket:
		return "UNIX stream client; socktype=2/5 selects datagram/seqpacket"
	case FeatureUNIXDatagram:
		return "UNIX stream client; socktype=2 selects datagram"
	default:
		return "UNIX stream client"
	}
}

// UnixListenHelp returns the description for UNIX-LISTEN addresses.
func UnixListenHelp() string {
	if FeatureUNIXSeqpacket {
		return "UNIX stream listener; socktype=5 selects seqpacket"
	}
	return "UNIX stream listener"
}

// UnixSocktypeHelp returns the description for the socktype option.
func UnixSocktypeHelp() string {
	switch {
	case FeatureUNIXSeqpacket:
		return "UNIX type: 1=stream, 2=datagram, 5=seqpacket"
	case FeatureUNIXDatagram:
		return "UNIX type: 1=stream, 2=datagram"
	default:
		return "UNIX type: 1=stream"
	}
}
