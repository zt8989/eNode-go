package ed2k

import (
	"enode/storage"
)

const minZlibPayloadOnSend = 128

type ServerConfig struct {
	Name        string
	Description string
	Address     string
	Hash        []byte
	TCPPort     uint16
	TCPFlags    uint32
	// IPv6 is the server's own public IPv6 (16 network-order bytes), advertised as
	// a CT_MOD_SVR_IP_V6 (0xaf) hash tag in OP_SERVERIDENT. Empty omits the tag.
	IPv6 []byte
}

type LoginRequest struct {
	Hash []byte
	ID   uint32
	Port uint16
	Tags []NamedTag
}

func ParseLoginRequest(data *Buffer) (LoginRequest, error) {
	out := LoginRequest{}
	hash := data.Get(16)
	if len(hash) != 16 {
		return out, ErrOutOfBounds
	}
	out.Hash = append([]byte(nil), hash...)
	id, err := data.GetUInt32LE()
	if err != nil {
		return out, err
	}
	out.ID = id
	port, err := data.GetUInt16LE()
	if err != nil {
		return out, err
	}
	out.Port = port
	tags, err := data.GetTags()
	if err != nil {
		return out, err
	}
	out.Tags = tags
	return out, nil
}

// SourceFormat selects how a found-sources reply encodes each source.
type SourceFormat int

const (
	// FormatClassic is the standard OP_FOUNDSOURCES layout, byte-identical to the
	// pre-IPv6 output. Safe for every client.
	FormatClassic SourceFormat = iota
	// FormatSentinel is FormatClassic plus the eMuleAI 0xFFFFFFFF+16-byte sentinel
	// for sources whose only routable address is IPv6. It desyncs a client that
	// lacks the sentinel parser, so it may only be sent to a session known to carry
	// it (connected over IPv6 or having sent CT_MOD_IP_V6).
	FormatSentinel
)

func BuildFoundSourcesPacket(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	return buildFoundSourcesPacketWithOpcode(OpFoundSources, fileHash, sources, false, FormatClassic)
}

func BuildFoundSourcesObfuPacket(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	return buildFoundSourcesPacketWithOpcode(OpFoundSourcesObfu, fileHash, sources, true, FormatClassic)
}

// BuildFoundSourcesSentinelPacket builds an OP_FOUNDSOURCES(_OBFU) reply that
// encodes IPv6-only sources with the sentinel form. Caller must have verified the
// requesting session parses it.
func BuildFoundSourcesSentinelPacket(fileHash []byte, sources []storage.Source, obfu bool) (*Buffer, error) {
	opcode := OpFoundSources
	if obfu {
		opcode = OpFoundSourcesObfu
	}
	return buildFoundSourcesPacketWithOpcode(opcode, fileHash, sources, obfu, FormatSentinel)
}

// hasHighID reports whether an ed2k ClientID is a routable HighID (a packed
// public IPv4) rather than a LowID handle or the unset 0. A source with a HighID
// is directly reachable over IPv4, so it is never replaced by the IPv6 sentinel.
func hasHighID(id uint32) bool {
	return id != 0 && !isLowID(id)
}

// sentinelForSource reports whether a source should be published with the IPv6
// sentinel: it has a verified-reachable IPv6 and no routable IPv4 HighID, so its
// only usable address is the IPv6. This matches eMuleAI's rule ("UINT_MAX means
// HighID with IPv6 only should not be listed here"): a LowID or v6-only source
// with a reachable v6 is better delivered as a direct v6 than as an uncallable
// LowID, and a v6-only source has no other reachable form at all.
func sentinelForSource(src storage.Source) bool {
	return sourceHasReachableIPv6(src) && !hasHighID(src.ID)
}

func buildFoundSourcesPacketWithOpcode(opcode uint8, fileHash []byte, sources []storage.Source, withObfuSettings bool, format SourceFormat) (*Buffer, error) {
	// The count is a single byte, so truncate the slice rather than the count:
	// uint8(256) is 0, which tells the client there are no sources and leaves the
	// 256 records that follow to be parsed as the next packet.
	sources = capWireSources(sources)
	pack := []PacketItem{
		{Type: TypeUint8, Value: opcode},
		{Type: TypeHash, Value: fileHash},
		{Type: TypeUint8, Value: uint8(len(sources))},
	}
	for _, src := range sources {
		useSentinel := format == FormatSentinel && sentinelForSource(src)
		// The port is sent verbatim for LowID sources too. There is no 0xFFFF
		// sentinel in the ed2k protocol: eMule stores whatever arrives here
		// (UpDownClient.cpp assigns m_userPort before it even looks at LowID) and
		// then republishes it through source exchange, so a fabricated port
		// propagates to peers that never contacted this server. Worse, ClientList
		// and DeadSourceList key on (IP, port), so the same peer learned via
		// OP_FOUNDSOURCES and via source exchange would never deduplicate.
		id := src.ID
		if useSentinel {
			id = SentinelIPv6ID
		}
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: id},
			PacketItem{Type: TypeUint16, Value: src.Port},
		)
		if withObfuSettings {
			// OP_FOUNDSOURCES_OBFU carries one "obfuscation settings" byte per source:
			// bit 0x01 supports crypt, 0x02 requests, 0x04 requires (matching eMule's
			// CreateSrcInfoPacket: (requires<<2)|(requests<<1)|(supports<<0)), and 0x80
			// meaning a 16-byte user hash follows.
			//
			// The hash is tied to crypt capability, as eMule expects (PartFile.cpp
			// AddSources warns when a hash is present for a source that isn't crypt
			// capable): send it only when the source advertised at least one crypt bit.
			// A non-crypt source therefore gets 0x00 and no hash — the requester used
			// OP_GETSOURCES_OBFU but cannot reach that peer obfuscated anyway.
			obf := src.CryptOptions & 0x07
			if obf != 0 && len(src.UserHash) == 16 {
				obf |= 0x80
			}
			pack = append(pack, PacketItem{Type: TypeUint8, Value: obf})
			if obf&0x80 != 0 {
				pack = append(pack, PacketItem{Type: TypeHash, Value: src.UserHash})
			}
		}
		if useSentinel {
			// The 16-byte IPv6 comes last, after any obfuscation fields — matching
			// eMuleAI PartFile.cpp AddSources, which reads it only after the crypt
			// options and user hash for an _OBFU source.
			pack = append(pack, PacketItem{Type: TypeHash, Value: src.IPv6})
		}
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func isLowID(id uint32) bool {
	return id > 0 && id <= 0x00FFFFFF
}

func BuildSearchResultPacket(files []storage.File) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpSearchResult},
		{Type: TypeUint32, Value: uint32(len(files))},
	}
	for _, file := range files {
		AddFile(&pack, SharedFile{
			Name:       file.Name,
			Size:       file.Size,
			Type:       file.Type,
			Sources:    file.Sources,
			Completed:  file.Completed,
			Title:      file.Title,
			Artist:     file.Artist,
			Album:      file.Album,
			Runtime:    file.Runtime,
			Bitrate:    file.Bitrate,
			Codec:      file.Codec,
			Hash:       file.Hash,
			SourceID:   file.SourceID,
			SourcePort: file.SourcePort,
		})
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildServerListPacket(servers []storage.Server) (*Buffer, error) {
	// Same single-byte count as the source lists, and ServersAll() is unbounded.
	if len(servers) > storage.MaxWireSources {
		servers = servers[:storage.MaxWireSources]
	}
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerList},
		{Type: TypeUint8, Value: uint8(len(servers))},
	}
	for _, s := range servers {
		ip, err := IPv4ToInt32LE(s.IP)
		if err != nil {
			return nil, err
		}
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: ip},
			PacketItem{Type: TypeUint16, Value: s.Port},
		)
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildServerStatusPacket(clients, files int) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerStatus},
		{Type: TypeUint32, Value: uint32(clients)},
		{Type: TypeUint32, Value: uint32(files)},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildIDChangePacket(id uint32, tcpFlags uint32) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpIDChange},
		{Type: TypeUint32, Value: id},
		{Type: TypeUint32, Value: tcpFlags},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildCallbackFailedPacket() (*Buffer, error) {
	pack := []PacketItem{{Type: TypeUint8, Value: OpCallbackFailed}}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildServerIdentPacket(conf ServerConfig) (*Buffer, error) {
	ip, err := IPv4ToInt32LE(conf.Address)
	if err != nil {
		return nil, err
	}
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: conf.Name},
		{Type: TypeString, Code: TagDescription, Data: conf.Description},
	}
	// Advertise the server's own IPv6 as a hash tag. eMule's OP_SERVERIDENT tag
	// loop consumes unknown name-IDs and unknown trailing tags without
	// disconnecting, so this is backward-compatible; a v6-aware client reads it.
	if len(conf.IPv6) == 16 {
		tags = append(tags, Tag{Type: TypeHash, Code: TagModSvrIPv6, Data: conf.IPv6})
	}
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerIdent},
		{Type: TypeHash, Value: conf.Hash},
		{Type: TypeUint32, Value: ip},
		{Type: TypeUint16, Value: conf.TCPPort},
		{Type: TypeTags, Value: tags},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildServerMessagePacket(message string) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerMessage},
		{Type: TypeString, Value: message},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

func BuildCallbackRequestedPacket(ipv4 uint32, port uint16) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpCallbackReqd},
		{Type: TypeUint32, Value: ipv4},
		{Type: TypeUint16, Value: port},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

// BuildCallbackRequestedIPv6Packet builds the OP_CALLBACKREQUESTED_IPV6 (0x26)
// packet the server sends to a firewalled callback target so it can call back to a
// requester over IPv6. It mirrors BuildCallbackRequestedPacket, replacing the
// uint32 IPv4 with the requester's 16-byte in6_addr (network byte order, emitted
// as a HASH just like the sentinel / CT_MOD_SVR_IP_V6 paths); no crypt trailer,
// matching the classic emitter above.
func BuildCallbackRequestedIPv6Packet(ipv6 []byte, port uint16) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpCallbackReqdIPv6},
		{Type: TypeHash, Value: ipv6},
		{Type: TypeUint16, Value: port},
	}
	packet, err := MakePacket(PrED2K, pack)
	if err != nil {
		return nil, err
	}
	return MaybeCompressTCPPacket(packet, minZlibPayloadOnSend)
}

// capWireSources truncates to what a single-byte count can describe. Applied at
// the wire layer as well as in the engines so the count and the record count
// cannot disagree, whichever engine supplied the slice.
func capWireSources(sources []storage.Source) []storage.Source {
	if len(sources) > storage.MaxWireSources {
		return sources[:storage.MaxWireSources]
	}
	return sources
}
