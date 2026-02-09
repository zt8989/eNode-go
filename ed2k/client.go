package ed2k

import (
	"encoding/binary"
	"errors"
)

const (
	MagicValueSync = 0x835E6FC4
	MagicValue203  = 203
	MagicValue34   = 34
)

type ClientConfig struct {
	EnableCrypt       bool
	Address           string
	TCPPort           uint16
	ConnectionTimeout int
	Hash              []byte
}

type Client struct {
	Config      ClientConfig
	CryptStatus int
	CryptMethod int
	Hash        []byte
	SendKey     *RC4Key
	RecvKey     *RC4Key
}

type HelloAnswer struct {
	Hash          []byte
	ID            uint32
	Port          uint16
	Tags          map[string]any
	ServerAddress uint32
	ServerPort    uint16
}

func NewClient(cfg ClientConfig) *Client {
	status := CsNone
	if cfg.EnableCrypt {
		status = CsUnknown
	}
	return &Client{
		Config:      cfg,
		CryptStatus: status,
	}
}

func (c *Client) BuildHandshake(randomProtocol uint8, randomKey uint32, pad []byte) ([]byte, error) {
	key := make([]byte, 21)
	if len(c.Hash) != 16 {
		return nil, ErrInvalidHashLength
	}
	copy(key, c.Hash)
	key[16] = MagicValue34
	binary.LittleEndian.PutUint32(key[17:], randomKey)
	sendSeed := MD5(key)

	copy(key, c.Hash)
	key[16] = MagicValue203
	recvSeed := MD5(key[:17])

	c.SendKey = RC4CreateKey(sendSeed, true)
	c.RecvKey = RC4CreateKey(recvSeed, true)

	enc := NewBuffer(4 + 1 + 1 + 1 + len(pad))
	_ = enc.PutUInt32LE(MagicValueSync)
	_ = enc.PutUInt8(uint8(EmSupported))
	_ = enc.PutUInt8(uint8(EmPreferred))
	_ = enc.PutUInt8(uint8(len(pad)))
	enc.PutBuffer(pad)
	encPayload := RC4Crypt(enc.Bytes(), len(enc.Bytes()), c.SendKey)

	out := NewBuffer(1 + 4 + len(encPayload))
	_ = out.PutUInt8(randomProtocol)
	_ = out.PutUInt32LE(randomKey)
	out.PutBuffer(encPayload)
	c.CryptStatus = CsNegotiating
	return out.Bytes(), nil
}

func (c *Client) Decrypt(data []byte) ([]byte, bool, error) {
	switch c.CryptStatus {
	case CsEncrypting:
		return RC4Crypt(data, len(data), c.RecvKey), false, nil
	case CsNegotiating:
		dec := RC4Crypt(data, len(data), c.RecvKey)
		b := NewBufferFromBytes(dec)
		sync, err := b.GetUInt32LE()
		if err != nil {
			return nil, false, err
		}
		if sync != MagicValueSync {
			c.CryptStatus = CsNone
			return nil, false, errors.New("bad handshake answer received")
		}
		method, err := b.GetUInt8()
		if err != nil {
			return nil, false, err
		}
		c.CryptMethod = int(method)
		padLen, err := b.GetUInt8()
		if err != nil {
			return nil, false, err
		}
		_ = b.Get(int(padLen))
		c.CryptStatus = CsEncrypting
		return nil, true, nil
	case CsNone:
		return data, false, nil
	default:
		return data, false, nil
	}
}

func (c *Client) BuildHelloPacket() (*Buffer, error) {
	addr, err := IPv4ToInt32LE(c.Config.Address)
	if err != nil {
		return nil, err
	}
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: ENodeName},
		{Type: TypeUint32, Code: TagVersion, Data: uint32(ENodeVersionInt)},
	}
	items := []PacketItem{
		{Type: TypeUint8, Value: OpHello},
		{Type: TypeUint8, Value: uint8(16)},
		{Type: TypeHash, Value: c.Config.Hash},
		{Type: TypeUint32, Value: addr},
		{Type: TypeUint16, Value: c.Config.TCPPort},
		{Type: TypeTags, Value: tags},
		{Type: TypeUint32, Value: addr},
		{Type: TypeUint16, Value: c.Config.TCPPort},
	}
	return MakePacket(PrED2K, items)
}

func ReadOpHelloAnswer(data *Buffer) (HelloAnswer, error) {
	out := HelloAnswer{Tags: map[string]any{}}
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
	for _, t := range tags {
		out.Tags[t.Name] = t.Value
	}
	serverAddress, err := data.GetUInt32LE()
	if err != nil {
		return out, err
	}
	out.ServerAddress = serverAddress
	serverPort, err := data.GetUInt16LE()
	if err != nil {
		return out, err
	}
	out.ServerPort = serverPort
	return out, nil
}
