package ed2k

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

type PacketItem struct {
	Type  uint8
	Value any
}

type SharedFile struct {
	Name       string
	Size       uint64
	Type       string
	Sources    uint32
	Completed  uint32
	Title      string
	Artist     string
	Album      string
	Runtime    uint32
	Bitrate    uint32
	Codec      string
	Hash       []byte
	SourceID   uint32
	SourcePort uint16
}

type CryptState interface {
	CryptStatus() int
	Process(*Buffer) error
}

type Packet struct {
	Protocol  uint8
	Size      uint32
	Code      uint8
	Status    int
	Data      *Buffer
	HasExcess bool
	Excess    []byte
}

func NewPacket() *Packet {
	return &Packet{
		Status: PsNew,
		Data:   NewBuffer(0),
	}
}

func itemSize(item PacketItem) (int, error) {
	switch item.Type {
	case TypeUint8:
		return 1, nil
	case TypeUint16:
		return 2, nil
	case TypeUint32:
		return 4, nil
	case TypeString:
		v, ok := item.Value.(string)
		if !ok {
			return 0, ErrUnsupportedTag
		}
		return 2 + len([]byte(v)), nil
	case TypeHash:
		return 16, nil
	case TypeTags:
		v, ok := item.Value.([]Tag)
		if !ok {
			return 0, ErrUnsupportedTag
		}
		return TagsLength(v)
	default:
		return 0, fmt.Errorf("%w: 0x%x", ErrUnsupportedTag, item.Type)
	}
}

func putItem(b *Buffer, item PacketItem) error {
	switch item.Type {
	case TypeUint8:
		switch v := item.Value.(type) {
		case uint8:
			return b.PutUInt8(v)
		case int:
			return b.PutUInt8(uint8(v))
		}
	case TypeUint16:
		switch v := item.Value.(type) {
		case uint16:
			return b.PutUInt16LE(v)
		case int:
			return b.PutUInt16LE(uint16(v))
		}
	case TypeUint32:
		switch v := item.Value.(type) {
		case uint32:
			return b.PutUInt32LE(v)
		case int:
			return b.PutUInt32LE(uint32(v))
		}
	case TypeString:
		if v, ok := item.Value.(string); ok {
			return b.PutString(v)
		}
	case TypeHash:
		if v, ok := item.Value.([]byte); ok {
			return b.PutHash(v)
		}
	case TypeTags:
		if v, ok := item.Value.([]Tag); ok {
			return b.PutTags(v)
		}
	}
	return ErrUnsupportedTag
}

func MakePacket(protocol uint8, items []PacketItem) (*Buffer, error) {
	size := 0
	for _, item := range items {
		l, err := itemSize(item)
		if err != nil {
			return nil, err
		}
		size += l
	}
	buf := NewBuffer(5 + size)
	if err := buf.PutUInt8(protocol); err != nil {
		return nil, err
	}
	if err := buf.PutUInt32LE(uint32(size)); err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := putItem(buf, item); err != nil {
			return nil, err
		}
	}
	buf.Pos(0)
	return buf, nil
}

func MakeUDPPacket(protocol uint8, items []PacketItem) (*Buffer, error) {
	size := 0
	for _, item := range items {
		l, err := itemSize(item)
		if err != nil {
			return nil, err
		}
		size += l
	}
	buf := NewBuffer(1 + size)
	if err := buf.PutUInt8(protocol); err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := putItem(buf, item); err != nil {
			return nil, err
		}
	}
	buf.Pos(0)
	return buf, nil
}

// MaybeCompressTCPPacket converts a normal TCP packet into PR_ZLIB format when:
// 1) payload length after opcode is at least minPayloadLen, and
// 2) zlib-compressed payload is smaller than the original payload.
func MaybeCompressTCPPacket(packet *Buffer, minPayloadLen int) (*Buffer, error) {
	if packet == nil {
		return nil, ErrOutOfBounds
	}
	raw := packet.Bytes()
	if len(raw) < 6 {
		return packet, nil
	}
	proto := raw[0]
	if proto != PrED2K && proto != PrEMule {
		return packet, nil
	}
	payload := raw[6:]
	if len(payload) < minPayloadLen {
		return packet, nil
	}

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if compressed.Len() >= len(payload) {
		return packet, nil
	}

	out := NewBuffer(6 + compressed.Len())
	_ = out.PutUInt8(PrZlib)
	_ = out.PutUInt32LE(uint32(compressed.Len() + 1))
	_ = out.PutUInt8(raw[5])
	out.PutBuffer(compressed.Bytes())
	out.Pos(0)
	return out, nil
}

func InflateZlibPayload(payload []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func AddFile(packet *[]PacketItem, file SharedFile) {
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: file.Name},
		{Type: TypeUint32, Code: TagSize, Data: uint32(file.Size % 0x100000000)},
		{Type: TypeString, Code: TagType, Data: file.Type},
		{Type: TypeUint32, Code: TagSources, Data: file.Sources},
		{Type: TypeUint32, Code: TagCompleteSources, Data: file.Completed},
	}
	if file.Size >= 0x100000000 {
		tags = append(tags, Tag{
			Type: TypeUint32, Code: TagSizeHi, Data: uint32(file.Size / 0x100000000),
		})
	}
	if file.Title != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMediaTitle, Data: file.Title})
	}
	if file.Artist != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMediaArtist, Data: file.Artist})
	}
	if file.Album != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMediaAlbum, Data: file.Album})
	}
	if file.Runtime > 0 {
		tags = append(tags, Tag{Type: TypeUint32, Code: TagMediaLength, Data: file.Runtime})
	}
	if file.Bitrate > 0 {
		tags = append(tags, Tag{Type: TypeUint32, Code: TagMediaBitrate, Data: file.Bitrate})
	}
	if file.Codec != "" {
		tags = append(tags, Tag{Type: TypeString, Code: TagMediaCodec, Data: file.Codec})
	}
	*packet = append(*packet,
		PacketItem{Type: TypeHash, Value: file.Hash},
		PacketItem{Type: TypeUint32, Value: file.SourceID},
		PacketItem{Type: TypeUint16, Value: file.SourcePort},
		PacketItem{Type: TypeTags, Value: tags},
	)
}

func (p *Packet) Init(buffer *Buffer, crypt CryptState) error {
	p.HasExcess = false
	protocol, err := buffer.GetUInt8()
	if err != nil {
		return err
	}
	p.Protocol = protocol

	if p.Protocol == PrED2K || p.Protocol == PrZlib || p.Protocol == PrEMule {
		size, err := buffer.GetUInt32LE()
		if err != nil {
			return err
		}
		if size == 0 {
			return ErrOutOfBounds
		}
		p.Size = size - 1
		code, err := buffer.GetUInt8()
		if err != nil {
			return err
		}
		p.Code = code
		p.Data = NewBuffer(int(p.Size))
		p.Append(buffer.Get())
		return nil
	}

	if crypt != nil && (crypt.CryptStatus() == CsUnknown || crypt.CryptStatus() == CsNegotiating) {
		return crypt.Process(buffer)
	}
	return nil
}

func (p *Packet) Append(chunk []byte) {
	received := p.Data.Pos()
	p.Data.PutBuffer(chunk)
	received += len(chunk)
	if uint32(received) == p.Size {
		p.Status = PsReady
		p.HasExcess = false
		return
	}
	if received < len(p.Data.Bytes()) {
		p.Status = PsWaitingData
		p.HasExcess = false
		return
	}
	p.Status = PsReady
	p.HasExcess = true
	excess := received - int(p.Size)
	if excess > 0 && excess <= len(chunk) {
		p.Excess = append([]byte(nil), chunk[len(chunk)-excess:]...)
	}
}
