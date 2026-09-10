package optionmeta

// ValueKind selects the CLI validator. Implementations live in the CLI
// (and ioctl in xio). Zero means no dedicated validator.
type ValueKind uint8

const (
	ValueNone ValueKind = iota
	RequiredString
	OptionalBool
	OptionalSignedInteger
	OptionalByte
	OptionalInteger0
	IntegerMin0
	IntegerMin1
	IntegerMinNeg1
	Duration
	Octal777
	Octal7777
	SizeT
	OptionalInt64
	Int64
	PositiveInt64
	IntegerRange0_2
	IntegerRange256_65507
	ResNSAddr
	NoValue
	Shut
	SockoptBin
	SockoptInt
	SockoptString
	GenericIoctl
	UnixTightSocklen
)
