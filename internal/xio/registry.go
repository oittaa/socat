package xio

import (
	"sort"
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
	OptionCaps  []string      // Extra option capabilities merged with DerivedOptionCaps
}

type addressRegistry struct {
	mu           sync.RWMutex
	openers      map[string]Opener
	descsByName  map[string]AddressDesc
	addrsByGroup map[string][]AddressDesc
	groupOrder   []string
}

func newAddressRegistry() *addressRegistry {
	return &addressRegistry{
		openers:      make(map[string]Opener),
		descsByName:  make(map[string]AddressDesc),
		addrsByGroup: make(map[string][]AddressDesc),
	}
}

var registeredAddresses = newAddressRegistry()

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
	registeredAddresses.register(desc)
}

func (r *addressRegistry) register(desc AddressDesc) {
	name := strings.ToUpper(strings.TrimSpace(desc.Name))
	if name == "" {
		panic("xio: address registration requires a name")
	}
	desc.Name = name
	desc.OptionCaps = mergeOptionCaps(DerivedOptionCaps(desc.Name, desc.Group), desc.OptionCaps)

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.descsByName[name]; exists {
		panic("xio: duplicate address registration: " + name)
	}
	r.descsByName[name] = desc
	if desc.Opener != nil {
		r.openers[name] = desc.Opener
	}
	if desc.Group != "" && desc.Syntax != "" {
		if _, exists := r.addrsByGroup[desc.Group]; !exists {
			r.groupOrder = append(r.groupOrder, desc.Group)
		}
		r.addrsByGroup[desc.Group] = append(r.addrsByGroup[desc.Group], desc)
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
	registeredAddresses.mu.RLock()
	defer registeredAddresses.mu.RUnlock()
	fn, ok := registeredAddresses.openers[strings.ToUpper(typ)]
	return fn, ok
}

// DefaultHelpGroupOrder is the -h section order.
func DefaultHelpGroupOrder() []string {
	return append([]string(nil), defaultGroupOrder...)
}

// AddressRegistration is a snapshot of one registered address type.
type AddressRegistration struct {
	Name       string
	Group      string
	Syntax     string
	Enabled    bool
	OptionCaps []string
}

// AddressRegistrationForType returns the registered metadata for one address
// keyword. It is used by the CLI to validate protocol-specific option scopes.
func AddressRegistrationForType(typ string) (AddressRegistration, bool) {
	return registeredAddresses.registration(typ)
}

func (r *addressRegistry) registration(typ string) (AddressRegistration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.descsByName[strings.ToUpper(typ)]
	if !ok {
		return AddressRegistration{}, false
	}
	return registrationSnapshot(d), true
}

// AddressRegistrations returns every opener and its help metadata.
func AddressRegistrations() []AddressRegistration {
	return registeredAddresses.registrations()
}

func (r *addressRegistry) registrations() []AddressRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]bool{}
	var out []AddressRegistration
	for _, group := range r.orderedGroupsLocked() {
		descs := r.addrsByGroup[group]
		for _, d := range descs {
			name := d.Name
			seen[name] = true
			out = append(out, registrationSnapshot(d))
		}
	}
	var hidden []string
	for name := range r.openers {
		if !seen[name] {
			hidden = append(hidden, name)
		}
	}
	sort.Strings(hidden)
	for _, name := range hidden {
		out = append(out, registrationSnapshot(r.descsByName[name]))
	}
	return out
}

func registrationSnapshot(d AddressDesc) AddressRegistration {
	return AddressRegistration{
		Name:       d.Name,
		Group:      d.Group,
		Syntax:     d.Syntax,
		Enabled:    d.Enabled == nil || d.Enabled(),
		OptionCaps: append([]string(nil), d.OptionCaps...),
	}
}

// HelpAddressGroups returns address groups and entries formatted for help output.
func HelpAddressGroups() []HelpAddrGroup {
	registeredAddresses.mu.RLock()
	defer registeredAddresses.mu.RUnlock()

	var res []HelpAddrGroup
	for _, g := range registeredAddresses.orderedGroupsLocked() {
		var list []HelpAddr
		for _, a := range registeredAddresses.addrsByGroup[g] {
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

func (r *addressRegistry) orderedGroupsLocked() []string {
	seen := make(map[string]bool)
	ordered := make([]string, 0, len(r.groupOrder))
	for _, group := range defaultGroupOrder {
		if _, ok := r.addrsByGroup[group]; ok {
			ordered = append(ordered, group)
			seen[group] = true
		}
	}
	for _, group := range r.groupOrder {
		if !seen[group] {
			ordered = append(ordered, group)
			seen[group] = true
		}
	}
	return ordered
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
