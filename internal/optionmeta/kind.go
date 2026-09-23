package optionmeta

// Kind is the grammar used to decode an option value once.
// Assignment of the decoded value stays with the option name.
type Kind uint8

const (
	KindNone Kind = iota
	KindBool
	KindNoValueName
	KindNoValueSpell
	KindString
	KindPresent
	KindOptionalString
	KindInt
	KindChildrenShutup
	KindOmittedInt
	KindSeek
	KindNonNeg
	KindSize
	KindDuration
	KindPositiveDuration
	KindSitout
	KindMode
	KindPort
	KindPresentPort
	KindEscape
	KindFlagInt
	KindReuseAddr
	KindSocketInt
	KindProtocol
	KindBacklog
	KindKeepCnt
	KindOwner
	KindFamily
	KindRange
	KindBind
	KindShut
	KindNamedShut
	KindFD
	KindResNS
	KindHTTPVersion
	KindCiphers
	KindALPN
	KindProtoMin
	KindProtoMax
	KindDTLSMTU
	KindTUNType
	KindTUNMTU
	KindMQPrio
	KindLink
	KindIoctl
	KindWinSize
	KindTermiosByte
	KindTermiosUint
	KindTermiosField
	KindTermiosFlags
	KindSockoptDalan
	KindSockoptInt
	KindSockoptString
	KindWordInt
	KindBuffer
	KindLinger
	KindTimeout
	KindBindDevice
	KindNamedWord
	KindNamedInt
	KindNamedCInt
	KindAncillary
	KindIPOptions
	KindRecvErr
	KindMTUDiscover
	KindRouterAlert
	KindTransparent
	KindGetOnly
	KindMcastJoin4
	KindMcastJoin6
	KindMcastIf
	KindMcastLoop4
	KindMcastTTL
	KindMcastLoop6
	KindMcastSource4
	KindMcastSource6
	KindHiddenString
	KindHiddenCompress
	KindHiddenBool
	KindHiddenInt
)
