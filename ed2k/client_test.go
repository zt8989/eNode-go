package ed2k

import "testing"

func TestBuildHelloPacket(t *testing.T) {
	c := NewClient(ClientConfig{
		EnableCrypt: false,
		Address:     "1.2.3.4",
		TCPPort:     4661,
		Hash:        []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	})
	buf, err := c.BuildHelloPacket()
	if err != nil {
		t.Fatal(err)
	}
	if buf.Bytes()[0] != PrED2K {
		t.Fatalf("bad protocol")
	}
}

func TestReadOpHelloAnswer(t *testing.T) {
	tags := []Tag{{Type: TypeString, Code: TagName, Data: "srv"}}
	tl, err := TagsLength(tags)
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuffer(16 + 4 + 2 + tl + 4 + 2)
	_ = b.PutHash([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	_ = b.PutUInt32LE(123)
	_ = b.PutUInt16LE(4662)
	_ = b.PutTags(tags)
	_ = b.PutUInt32LE(0x04030201)
	_ = b.PutUInt16LE(4661)
	b.Pos(0)

	info, err := ReadOpHelloAnswer(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != 123 || info.Port != 4662 || info.ServerPort != 4661 {
		t.Fatalf("unexpected hello answer: %+v", info)
	}
	if info.Tags["name"].(string) != "srv" {
		t.Fatalf("bad tags")
	}
}

func TestHandshakeAndDecryptNegotiation(t *testing.T) {
	c := NewClient(ClientConfig{EnableCrypt: true})
	c.Hash = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	_, err := c.BuildHandshake(0xaa, 0x11223344, []byte{9, 8, 7})
	if err != nil {
		t.Fatal(err)
	}

	// emulate server response encrypted with recv key stream.
	plain := NewBuffer(4 + 1 + 1 + 2)
	_ = plain.PutUInt32LE(MagicValueSync)
	_ = plain.PutUInt8(uint8(EmObfuscate))
	_ = plain.PutUInt8(2)
	plain.PutBuffer([]byte{1, 2})

	k := *c.RecvKey
	wire := RC4Crypt(plain.Bytes(), len(plain.Bytes()), &k)
	_, handshakeDone, err := c.Decrypt(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !handshakeDone || c.CryptStatus != CsEncrypting {
		t.Fatalf("handshake not done: status=%d", c.CryptStatus)
	}
}
