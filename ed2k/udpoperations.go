package ed2k

import "enode/storage"

type UDPConfig struct {
	Name           string
	Description    string
	DynIP          string
	UDPFlags       uint32
	UDPPortObf     uint16
	TCPPortObf     uint16
	UDPServerKey   uint32
	MaxConnections uint32
}

func BuildGlobSearchResPackets(files []storage.File) ([]*Buffer, error) {
	out := make([]*Buffer, 0, len(files))
	for _, file := range files {
		pack := []PacketItem{{Type: TypeUint8, Value: OpGlobSearchRes}}
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
		b, err := MakeUDPPacket(PrED2K, pack)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func BuildGlobFoundSourcesPacket(fileHash []byte, sources []storage.Source) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpGlobFoundSources},
		{Type: TypeHash, Value: fileHash},
		{Type: TypeUint8, Value: uint8(len(sources))},
	}
	for _, src := range sources {
		pack = append(pack,
			PacketItem{Type: TypeUint32, Value: src.ID},
			PacketItem{Type: TypeUint16, Value: src.Port},
		)
	}
	return MakeUDPPacket(PrED2K, pack)
}

func BuildGlobServStatResPacket(challenge uint32, cfg UDPConfig, clientsCount int, filesCount int, lowIDCount int) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpGlobServStatRes},
		{Type: TypeUint32, Value: challenge},
		{Type: TypeUint32, Value: uint32(clientsCount + 2000)},
		{Type: TypeUint32, Value: uint32(filesCount)},
		{Type: TypeUint32, Value: cfg.MaxConnections},
		{Type: TypeUint32, Value: uint32(10000)},
		{Type: TypeUint32, Value: uint32(20000)},
		{Type: TypeUint32, Value: cfg.UDPFlags},
		{Type: TypeUint32, Value: uint32(lowIDCount + 1000)},
		{Type: TypeUint16, Value: cfg.UDPPortObf},
		{Type: TypeUint16, Value: cfg.TCPPortObf},
		{Type: TypeUint32, Value: cfg.UDPServerKey},
	}
	return MakeUDPPacket(PrED2K, pack)
}

func BuildServerDescResOldPacket(name, desc string) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerDescRes},
		{Type: TypeString, Value: name},
		{Type: TypeString, Value: desc},
	}
	return MakeUDPPacket(PrED2K, pack)
}

func BuildServerDescResPacket(challenge uint32, cfg UDPConfig) (*Buffer, error) {
	pack := []PacketItem{
		{Type: TypeUint8, Value: OpServerDescRes},
		{Type: TypeUint32, Value: challenge},
		{Type: TypeTags, Value: []Tag{
			{Type: TypeString, Code: TagName, Data: cfg.Name},
			{Type: TypeString, Code: TagDescription, Data: cfg.Description},
			{Type: TypeString, Code: TagDynIP, Data: cfg.DynIP},
			{Type: TypeUint32, Code: TagVersion2, Data: uint32(ENodeVersionInt)},
			{Type: TypeString, Code: TagAuxPortsList, Data: ""},
		}},
	}
	return MakeUDPPacket(PrED2K, pack)
}
