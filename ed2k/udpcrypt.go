package ed2k

const (
	MagicValueUDPServerClient = 0xA5
	MagicValueUDPClientServer = 0x6B
	MagicValueUDPSyncClient   = 0x395F2EC1
	MagicValueUDPSyncServer   = 0x13EF24D5
)

type UDPCrypt struct {
	Status    int
	ServerKey uint32
}

func NewUDPCrypt(supportCrypt bool, serverKey uint32) *UDPCrypt {
	status := CsNone
	if supportCrypt {
		status = CsEncrypting
	}
	return &UDPCrypt{
		Status:    status,
		ServerKey: serverKey,
	}
}

func (u *UDPCrypt) rc4Key(magic byte, randomKey uint16) *RC4Key {
	key := make([]byte, 7)
	b := NewBufferFromBytes(key)
	_ = b.PutUInt32LE(u.ServerKey)
	_ = b.PutUInt8(magic)
	_ = b.PutUInt16LE(randomKey)
	return RC4CreateKey(MD5(key), false)
}

func (u *UDPCrypt) Decrypt(buffer []byte) []byte {
	if u.Status != CsEncrypting {
		return buffer
	}
	b := NewBufferFromBytes(buffer)
	protocol, err := b.GetUInt8()
	if err != nil {
		return buffer
	}
	// For server UDP packets, plaintext starts with PR_ED2K.
	// Obfuscated marker byte can legally collide with other protocol constants
	// (e.g. PR_EMULE/PR_ZLIB), so only PR_ED2K should bypass decryption here.
	if protocol == PrED2K {
		b.Pos(0)
		return b.Bytes()
	}
	clientKey, err := b.GetUInt16LE()
	if err != nil {
		return buffer
	}
	data := b.Get()
	dec := RC4Crypt(data, len(data), u.rc4Key(MagicValueUDPClientServer, clientKey))
	db := NewBufferFromBytes(dec)
	sync, err := db.GetUInt32LE()
	if err != nil || sync != MagicValueUDPSyncServer {
		return buffer
	}
	padLength, err := db.GetUInt8()
	if err != nil {
		return buffer
	}
	_ = db.Get(int(padLength))
	return db.Get()
}

func (u *UDPCrypt) Encrypt(buffer []byte) []byte {
	if u.Status != CsEncrypting {
		return buffer
	}
	randomKey := uint16(Rand(0xffff))
	enc := NewBuffer(len(buffer) + 5)
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(0)
	enc.PutBuffer(buffer)
	encrypted := RC4Crypt(enc.Bytes(), len(enc.Bytes()), u.rc4Key(MagicValueUDPServerClient, randomKey))

	out := NewBuffer(len(buffer) + 8)
	_ = out.PutUInt8(RandProtocol())
	_ = out.PutUInt16LE(randomKey)
	out.PutBuffer(encrypted)
	return out.Bytes()
}
