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
	GroupDTLS      = "Datagram TLS 1.3"
	GroupTLS       = "TLS (OPENSSL/SSL aliases)"
	GroupProxy     = "PROXY and SOCKS"
	GroupTUN       = "Linux TUN / INTERFACE"
	GroupWebSocket = "WebSocket (Go extra)" // #nosec G101 -- help section title, not a secret
	GroupQUIC      = "QUIC (Go extra, not HTTP/3)"
	GroupSCTP      = "SCTP (Linux)"
	GroupVSOCK     = "VSOCK (Linux)"
	GroupPOSIXMQ   = "POSIX message queues (Linux)"
)

// HelpAddr represents a single address entry in help output.
type HelpAddr struct {
	Name    string // Registered keyword, e.g. "TCP-CONNECT"
	Syntax  string
	Desc    string
	Aliases []string // Unregistered address aliases; printed at -hhh
}

// HelpAddrGroup represents a section of address types in help output.
type HelpAddrGroup struct {
	Title string
	Addrs []HelpAddr
}

// AddressDesc describes a registered address type.
// Each help line is its own descriptor (including aliases such as TCP-L).
type AddressDesc struct {
	Group       string        // Section title; use Group* constants
	Name        string        // Keyword, e.g. "TCP" or "TCP-L"
	Syntax      string        // Help syntax, e.g. "TCP:<host>:<port>"
	Desc        string        // Help description
	DynamicDesc func() string // Optional dynamic help description (e.g. UNIX capabilities)
	Enabled     func() bool   // Optional feature predicate. If nil, considered enabled.
	Opener      Opener        // Opener function handling this address
	OptionCaps  []string      // Address capability tokens for option-scope checks
	Aliases     []string      // Extra keywords that resolve to this descriptor; -hhh only
	// Directions is ModeRead, ModeWrite, or ModeRDWR (zero: both).
	Directions Mode
}

type addressRegistry struct {
	mu           sync.RWMutex
	openers      map[string]Opener
	descsByName  map[string]AddressDesc
	aliases      map[string]string // alias → registered Name
	addrsByGroup map[string][]AddressDesc
	groupOrder   []string
}

func newAddressRegistry() *addressRegistry {
	return &addressRegistry{
		openers:      make(map[string]Opener),
		descsByName:  make(map[string]AddressDesc),
		aliases:      make(map[string]string),
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
	GroupDTLS,
	GroupProxy,
	GroupTUN,
	GroupWebSocket,
	GroupQUIC,
	GroupSCTP,
	GroupVSOCK,
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
	if name == "-" {
		panic("xio: parser shorthand - must not be registered")
	}
	desc.Name = name
	desc.OptionCaps = uniqueCaps(desc.OptionCaps)
	if len(desc.OptionCaps) == 0 {
		panic("xio: address registration requires OptionCaps: " + name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.descsByName[name]; exists {
		panic("xio: duplicate address registration: " + name)
	}
	if _, exists := r.aliases[name]; exists {
		panic("xio: address registration collides with alias: " + name)
	}

	aliases := make([]string, 0, len(desc.Aliases))
	seen := map[string]bool{}
	for _, raw := range desc.Aliases {
		alias := strings.ToUpper(strings.TrimSpace(raw))
		if alias == "" || alias == name || alias == "-" {
			continue
		}
		if seen[alias] {
			continue
		}
		seen[alias] = true
		if _, exists := r.descsByName[alias]; exists {
			panic("xio: alias collides with registered address: " + alias)
		}
		if dest, exists := r.aliases[alias]; exists {
			panic("xio: duplicate address alias " + alias + " (already " + dest + ")")
		}
		r.aliases[alias] = name
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	desc.Aliases = aliases

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

// Register associates an address type name with an opener.
// It does not add a -h line; prefer RegisterAddress with Syntax set.
func Register(name string, fn Opener) {
	RegisterAddress(AddressDesc{
		Name:       name,
		Opener:     fn,
		OptionCaps: CapsFD,
	})
}

func lookupOpener(typ string) (Opener, bool) {
	return registeredAddresses.opener(typ)
}

func (r *addressRegistry) opener(typ string) (Opener, bool) {
	d, ok := r.resolve(typ)
	if !ok || d.Opener == nil {
		return nil, false
	}
	return d.Opener, true
}

// resolve returns the registered descriptor for typ. Direct RegisterAddress
// entries win. Otherwise Aliases on a registered descriptor are applied.
// Unsupported families (DCCP, UDP-Lite, readline) stay unknown because
// they are not registered. DCCP is an intentional compatibility exception,
// not backlog. Parser shorthand "-" → STDIO is handled in parse.ParseSpec.
func (r *addressRegistry) resolve(typ string) (AddressDesc, bool) {
	name := strings.ToUpper(strings.TrimSpace(typ))
	if name == "" || name == "-" {
		return AddressDesc{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if d, ok := r.descsByName[name]; ok {
		return d, true
	}
	if dest, ok := r.aliases[name]; ok {
		if d, ok := r.descsByName[dest]; ok {
			return d, true
		}
	}
	return AddressDesc{}, false
}

// AddressAliasMap returns alias → registered keyword for every alias this
// process registered. Direct RegisterAddress names are omitted.
func AddressAliasMap() map[string]string {
	return registeredAddresses.aliasMap()
}

func (r *addressRegistry) aliasMap() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.aliases))
	for alias, dest := range r.aliases {
		out[alias] = dest
	}
	return out
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
// keyword, including aliases whose canonical opener is registered. Direct
// RegisterAddress entries win over alias fallback. It is used by the CLI to
// validate protocol-specific option scopes.
func AddressRegistrationForType(typ string) (AddressRegistration, bool) {
	return registeredAddresses.registration(typ)
}

func (r *addressRegistry) registration(typ string) (AddressRegistration, bool) {
	d, ok := r.resolve(typ)
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
				Name:    a.Name,
				Syntax:  a.Syntax,
				Desc:    desc,
				Aliases: append([]string(nil), a.Aliases...),
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
