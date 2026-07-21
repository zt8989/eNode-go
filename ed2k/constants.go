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

// IPv6 source-exchange opcodes (eNode-go extension).
//
// These carry the richer tag-block source format (§Format 2 of the IPv6 plan): a
// client opts in by sending the request opcode, and the server answers in the
// extended layout only to such a client. The values are virgin space above the
// classic high-water marks (OP_GETSOURCES_OBFU 0x23, OP_SERVER_LIST_REQ2 0xa4)
// and are free across every surveyed eMule tree, so a legacy client never emits
// them and its ProcessPacket drops them with a harmless default case.
const (
	OpGetSourcesIPv6       uint8 = 0x24
	OpFoundSourcesIPv6     uint8 = 0x25
	OpGlobGetSourcesIPv6   uint8 = 0xa5
	OpGlobFoundSourcesIPv6 uint8 = 0xa6
)

// SentinelIPv6ID is the ClientID value that marks an IPv6-only source inside the
// classic OP_FOUNDSOURCES list: eMule reads 0xffffffff and then consumes 16 raw
// in6_addr bytes that follow the port (and, for _OBFU, the crypt fields). Only
// emitted to a session known to parse it — see the gating rule in the plan.
const SentinelIPv6ID uint32 = 0xffffffff

const (
	OpNatSync       uint8 = 0xe1
	OpNatPing       uint8 = 0xe2
	OpNatRegisterEx uint8 = 0xe3
	OpNatRegister   uint8 = 0xe4
	OpNatFailed     uint8 = 0xe5
	OpNatKeepAlive  uint8 = 0xe6
	OpNatSyncEx     uint8 = 0xe7
	OpNatReping     uint8 = 0xe8
	OpNatSync2      uint8 = 0xe9
	OpNatData       uint8 = 0xea
	OpNatAck        uint8 = 0xeb
	OpNatRst        uint8 = 0xef
)

const (
	TypeHash   uint8 = 0x01
	TypeString uint8 = 0x02
	TypeUint32 uint8 = 0x03
	TypeFloat  uint8 = 0x04
	TypeBool   uint8 = 0x05
	TypeBlob   uint8 = 0x07
	TypeUint16 uint8 = 0x08
	TypeUint8  uint8 = 0x09
	TypeBsob   uint8 = 0x0a
	TypeUint64 uint8 = 0x0b
	TypeTags   uint8 = 0x0f
)

const (
	PsNew              = 1
	PsReady            = 2
	PsWaitingData      = 3
	PsCryptNegotiating = 4
)

// MaxTCPPacketSize bounds the payload size a peer may declare in a TCP packet
// header. Without it, the 4-byte size field is allocated verbatim, so a 6-byte
// header can reserve ~4 GiB. eMule applies the same ceiling and drops the
// connection past it: see src/core/net/EMSocket.cpp, kMaxReadBuffer / kErrTooBig.
const MaxTCPPacketSize = 2_000_000

// maxHelloAnswerBytes caps what the firewall probe will accumulate from the
// peer it is probing.
//
// Defence in depth, not the primary bound: while readHelloAnswer rejects a
// declared size above MaxTCPPacketSize, every packet completes and is consumed
// once 5+size bytes arrive, so the reassembly buffer cannot exceed roughly
// MaxTCPPacketSize plus one read. This ceiling only matters if that size check
// is ever relaxed — which is exactly when it would be missed.
const maxHelloAnswerBytes = 4 * MaxTCPPacketSize

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
	// IPv6 MOD tags, allocated by eMuleAI (Opcodes.h) and reused here verbatim.
	// CT_MOD_IP_V6 carries a client's public IPv6 as a 16-byte HASH tag in
	// OP_LOGINREQUEST; CT_MOD_SVR_IP_V6 carries the server's own IPv6 as a HASH tag
	// in OP_SERVERIDENT.
	TagModIPv6    uint8 = 0xae
	TagModSvrIPv6 uint8 = 0xaf
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
	// FlagIPv6 advertises IPv6 support in the SRV_TCPFLG_* / SRV_UDPFLG_* word.
	// No eMule tree defines any server flag >= 0x1000; the only occupants are
	// ed2kNET's unofficial 0x1000/0x2000 (chacha20/aes256), so 0x4000 is the first
	// clean bit. Clients ignore unknown bits, so this is display/verify metadata.
	FlagIPv6 uint32 = 0x4000
)

const (
	ENodeVersionStr = "v0.04"
	ENodeVersionInt = 0x00000003
	ENodeName       = "eNode"
)
