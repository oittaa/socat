// Package optionmeta owns option declarations shared by parse, cli, and xio.
// It imports none of those packages.
//
// Each family file declares its options. catalog.go groups them for help and
// indexes their spellings. An option's Scope is independent of its help section.
//
// The flow is:
//   - parse uses ParserCanonical and IsPathValue while reading an address.
//   - cli uses Lookup to validate names and address scope, and Sections for help.
//     Static value contracts live in addrconfig.Decode.
//   - xio openers apply options or reject them. TLS and get-only IP diagnostics
//     use Lookup; ancillary effects remain in xio/ip_ancillary_matrix.go.
//
// Add an option in its family file and implement its effect in the relevant
// opener. Scope documents CLI acceptance; membership does not prove application.
package optionmeta
