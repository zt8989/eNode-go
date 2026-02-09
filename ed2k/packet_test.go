package ed2k

import (
	"bytes"
	"testing"
)

type mockCrypt struct {
	status int
	called bool
}

func (m *mockCrypt) CryptStatus() int { return m.status }
func (m *mockCrypt) Process(_ *Buffer) error {
	m.called = true
	return nil
}

func TestMakePacketAndUDPPacket(t *testing.T) {
	items := []PacketItem{
		{Type: TypeUint8, Value: uint8(0xaa)},
		{Type: TypeUint16, Value: uint16(0xbbcc)},
		{Type: TypeUint32, Value: uint32(0x11223344)},
		{Type: TypeString, Value: "xy"},
	}

	tcp, err := MakePacket(PrED2K, items)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := MakeUDPPacket(PrEMule, items)
	if err != nil {
		t.Fatal(err)
	}

	if tcp.Bytes()[0] != PrED2K {
		t.Fatalf("tcp protocol mismatch: 0x%x", tcp.Bytes()[0])
	}
	if udp.Bytes()[0] != PrEMule {
		t.Fatalf("udp protocol mismatch: 0x%x", udp.Bytes()[0])
	}
	if len(tcp.Bytes()) != len(udp.Bytes())+4 {
		t.Fatalf("unexpected sizes: tcp=%d udp=%d", len(tcp.Bytes()), len(udp.Bytes()))
	}
}

func TestAddFileAddsExpectedItems(t *testing.T) {
	items := make([]PacketItem, 0)
	hash := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	AddFile(&items, SharedFile{
		Name:       "song.mp3",
		Size:       0x100000001,
		Type:       "Audio",
		Sources:    10,
		Completed:  3,
		Title:      "Title",
		Artist:     "Artist",
		Album:      "Album",
		Runtime:    120,
		Bitrate:    320,
		Codec:      "mp3",
		Hash:       hash,
		SourceID:   123,
		SourcePort: 4662,
	})

	if len(items) != 4 {
		t.Fatalf("unexpected item count: %d", len(items))
	}
	if !bytes.Equal(items[0].Value.([]byte), hash) {
		t.Fatalf("hash mismatch")
	}
	tags, ok := items[3].Value.([]Tag)
	if !ok {
		t.Fatalf("tags not found")
	}
	foundSizeHi := false
	for _, tag := range tags {
		if tag.Code == TagSizeHi {
			foundSizeHi = true
		}
	}
	if !foundSizeHi {
		t.Fatalf("expected sizehi tag")
	}
}

func TestPacketInitAndAppend(t *testing.T) {
	// protocol + payload size(with opcode) + opcode + payload "AB"
	wire := NewBufferFromBytes([]byte{
		PrED2K, 0x03, 0x00, 0x00, 0x00, 0x34, 'A', 'B',
	})
	p := NewPacket()
	if err := p.Init(wire, nil); err != nil {
		t.Fatal(err)
	}
	if p.Protocol != PrED2K || p.Code != 0x34 || p.Size != 2 {
		t.Fatalf("header mismatch: %+v", p)
	}
	if p.Status != PsReady {
		t.Fatalf("status mismatch: %d", p.Status)
	}
	if string(p.Data.Bytes()) != "AB" {
		t.Fatalf("payload mismatch: %q", string(p.Data.Bytes()))
	}
}

func TestPacketAppendWithExcess(t *testing.T) {
	p := NewPacket()
	p.Size = 2
	p.Data = NewBuffer(2)
	p.Append([]byte{'A', 'B', 'C', 'D'})
	if !p.HasExcess {
		t.Fatalf("expected excess")
	}
	if !bytes.Equal(p.Excess, []byte{'C', 'D'}) {
		t.Fatalf("excess mismatch: %v", p.Excess)
	}
}

func TestPacketInitUnknownProtocolUsesCrypt(t *testing.T) {
	wire := NewBufferFromBytes([]byte{0xff, 0x11, 0x22})
	p := NewPacket()
	m := &mockCrypt{status: CsUnknown}
	if err := p.Init(wire, m); err != nil {
		t.Fatal(err)
	}
	if !m.called {
		t.Fatalf("expected crypt to be called")
	}
}
