package ed2k

import (
	"enode/storage"
)

type ServerConfig struct {
	Name        string
	Description string
	Address     string
	Hash        []byte
	TCPPort     uint16
	TCPFlags    uint32
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

func BuildFoundSourcesPacket(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpFoundSources},
		{Type: TypeHash, Value: fileHash},
		{Type: TypeUint8, Value: uint8(len(sources))},
	}
	for _, src := range sources {
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: src.ID},
			PacketItem{Type: TypeUint16, Value: src.Port},
		)
	}
	return MakePacket(PrED2K, pack)
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
	return MakePacket(PrED2K, pack)
}

func BuildServerListPacket(servers []storage.Server) (*Buffer, error) {
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
	return MakePacket(PrED2K, pack)
}

func BuildServerStatusPacket(clients, files int) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerStatus},
		{Type: TypeUint32, Value: uint32(clients)},
		{Type: TypeUint32, Value: uint32(files)},
	}
	return MakePacket(PrED2K, pack)
}

func BuildIDChangePacket(id uint32, tcpFlags uint32) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpIDChange},
		{Type: TypeUint32, Value: id},
		{Type: TypeUint32, Value: tcpFlags},
	}
	return MakePacket(PrED2K, pack)
}

func BuildCallbackFailedPacket() (*Buffer, error) {
	pack := []PacketItem{{Type: TypeUint8, Value: OpCallbackFailed}}
	return MakePacket(PrED2K, pack)
}

func BuildServerIdentPacket(conf ServerConfig) (*Buffer, error) {
	ip, err := IPv4ToInt32LE(conf.Address)
	if err != nil {
		return nil, err
	}
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerIdent},
		{Type: TypeHash, Value: conf.Hash},
		{Type: TypeUint32, Value: ip},
		{Type: TypeUint16, Value: conf.TCPPort},
		{Type: TypeTags, Value: []Tag{
			{Type: TypeString, Code: TagName, Data: conf.Name},
			{Type: TypeString, Code: TagDescription, Data: conf.Description},
		}},
	}
	return MakePacket(PrED2K, pack)
}

func BuildServerMessagePacket(message string) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerMessage},
		{Type: TypeString, Value: message},
	}
	return MakePacket(PrED2K, pack)
}

func BuildCallbackRequestedPacket(ipv4 uint32, port uint16) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpCallbackReqd},
		{Type: TypeUint32, Value: ipv4},
		{Type: TypeUint16, Value: port},
	}
	return MakePacket(PrED2K, pack)
}
