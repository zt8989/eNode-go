package ed2k

const (
	PrED2K  uint8 = 0xe3
	PrEMule uint8 = 0xc5
	PrZlib  uint8 = 0xd4
	PrNat   uint8 = 0xf1
)

const (
	OpLoginRequest     uint8 = 0x01
	OpHello            uint8 = 0x01
	OpHelloAnswer      uint8 = 0x4c
	OpServerMessage    uint8 = 0x38
	OpServerStatus     uint8 = 0x34
	OpIDChange         uint8 = 0x40
	OpGetServerList    uint8 = 0x14
	OpOfferFiles       uint8 = 0x15
	OpServerList       uint8 = 0x32
	OpServerIdent      uint8 = 0x41
	OpGetSources       uint8 = 0x19
	OpFoundSources     uint8 = 0x42
	OpSearchRequest    uint8 = 0x16
	OpSearchResult     uint8 = 0x33
	OpCallbackRequest  uint8 = 0x1c
	OpCallbackReqd     uint8 = 0x35
	OpCallbackFailed   uint8 = 0x36
	OpGetSourcesObfu   uint8 = 0x23
	OpFoundSourcesObfu uint8 = 0x44
	OpGlobSearchReq3   uint8 = 0x90
	OpGlobSearchReq2   uint8 = 0x92
	OpGlobGetSources2  uint8 = 0x94
	OpGlobServStatReq  uint8 = 0x96
	OpGlobServStatRes  uint8 = 0x97
	OpGlobSearchReq    uint8 = 0x98
	OpGlobSearchRes    uint8 = 0x99
	OpGlobGetSources   uint8 = 0x9a
	OpGlobFoundSources uint8 = 0x9b
	OpServerDescReq    uint8 = 0xa2
	OpServerDescRes    uint8 = 0xa3
)

const (
	OpNatSync     uint8 = 0xe1
	OpNatPing     uint8 = 0xe2
	OpNatRegister uint8 = 0xe4
	OpNatFailed   uint8 = 0xe5
	OpNatReping   uint8 = 0xe8
	OpNatSync2    uint8 = 0xe9
	OpNatData     uint8 = 0xea
	OpNatAck      uint8 = 0xeb
	OpNatRst      uint8 = 0xef
)

const (
	TypeHash   uint8 = 0x01
	TypeString uint8 = 0x02
	TypeUint32 uint8 = 0x03
	TypeFloat  uint8 = 0x04
	TypeUint16 uint8 = 0x08
	TypeUint8  uint8 = 0x09
	TypeTags   uint8 = 0x0f
)

const (
	PsNew              = 1
	PsReady            = 2
	PsWaitingData      = 3
	PsCryptNegotiating = 4
)

const (
	CsNone        = 0
	CsUnknown     = 1
	CsNegotiating = 4
	CsEncrypting  = 5
)

const (
	TagName            uint8 = 0x01
	TagSize            uint8 = 0x02
	TagType            uint8 = 0x03
	TagFormat          uint8 = 0x04
	TagVersion         uint8 = 0x11
	TagVersion2        uint8 = 0x91
	TagPort            uint8 = 0x0f
	TagDescription     uint8 = 0x0b
	TagDynIP           uint8 = 0x85
	TagSources         uint8 = 0x15
	TagCompleteSources uint8 = 0x30
	TagMuleVersion     uint8 = 0xfb
	TagFlags           uint8 = 0x20
	TagRating          uint8 = 0xf7
	TagSizeHi          uint8 = 0x3a
	TagMediaArtist     uint8 = 0xd0
	TagMediaAlbum      uint8 = 0xd1
	TagMediaTitle      uint8 = 0xd2
	TagMediaLength     uint8 = 0xd3
	TagMediaBitrate    uint8 = 0xd4
	TagMediaCodec      uint8 = 0xd5
	TagSearchTree      uint8 = 0x0e
	TagEmuleUDPPorts   uint8 = 0xf9
	TagEmuleOptions1   uint8 = 0xfa
	TagEmuleOptions2   uint8 = 0xfe
	TagAuxPortsList    uint8 = 0x93
)

const (
	ValPartialID    uint32 = 0xfcfcfcfc
	ValPartialPort  uint16 = 0xfcfc
	ValCompleteID   uint32 = 0xfbfbfbfb
	ValCompletePort uint16 = 0xfbfb
)

const (
	FlagZlib          uint32 = 0x0001
	FlagIPInLogin     uint32 = 0x0002
	FlagAuxPort       uint32 = 0x0004
	FlagNewTags       uint32 = 0x0008
	FlagUnicode       uint32 = 0x0010
	FlagLargeFiles    uint32 = 0x0100
	FlagSupportCrypt  uint32 = 0x0200
	FlagRequestCrypt  uint32 = 0x0400
	FlagRequireCrypt  uint32 = 0x0800
	FlagUdpExtSources uint32 = 0x0001
	FlagUdpExtFiles   uint32 = 0x0002
	FlagUdpExtSrc2    uint32 = 0x0020
	FlagUdpObfusc     uint32 = 0x0200
	FlagTcpObfusc     uint32 = 0x0400
)

const (
	ENodeVersionStr = "v0.04"
	ENodeVersionInt = 0x00000003
	ENodeName       = "eNode"
)
