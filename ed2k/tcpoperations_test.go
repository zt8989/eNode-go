package ed2k

import (
	"enode/storage"
	"testing"
)

func TestParseLoginRequest(t *testing.T) {
	tags := []Tag{{Type: TypeString, Code: TagName, Data: "node"}}
	l, _ := TagsLength(tags)
	b := NewBuffer(16 + 4 + 2 + l)
	_ = b.PutHash([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	_ = b.PutUInt32LE(123)
	_ = b.PutUInt16LE(4662)
	_ = b.PutTags(tags)
	b.Pos(0)
	req, err := ParseLoginRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if req.ID != 123 || req.Port != 4662 || req.Tags[0].Name != "name" {
		t.Fatalf("bad parse: %+v", req)
	}
}

func TestBuildServerPackets(t *testing.T) {
	msg, err := BuildServerMessagePacket("hello")
	if err != nil {
		t.Fatal(err)
	}
	if msg.Bytes()[0] != PrED2K {
		t.Fatalf("protocol mismatch")
	}

	st, err := BuildServerStatusPacket(10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if st.Bytes()[5] != OpServerStatus {
		t.Fatalf("opcode mismatch")
	}

	idc, err := BuildIDChangePacket(123, 0x10)
	if err != nil {
		t.Fatal(err)
	}
	if idc.Bytes()[5] != OpIDChange {
		t.Fatalf("opcode mismatch")
	}
}

func TestBuildSearchAndSources(t *testing.T) {
	fileHash := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	fp, err := BuildFoundSourcesPacket(fileHash, []storage.Source{{ID: 11, Port: 22}})
	if err != nil {
		t.Fatal(err)
	}
	if fp.Bytes()[5] != OpFoundSources {
		t.Fatalf("opcode mismatch")
	}
	fpObfu, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{ID: 11, Port: 22}})
	if err != nil {
		t.Fatal(err)
	}
	if fpObfu.Bytes()[5] != OpFoundSourcesObfu {
		t.Fatalf("obfu opcode mismatch")
	}
	if len(fpObfu.Bytes()) != len(fp.Bytes())+1 {
		t.Fatalf("obfu packet size mismatch: normal=%d obfu=%d", len(fp.Bytes()), len(fpObfu.Bytes()))
	}
	// protocol(1)+size(4)+opcode(1)+hash(16)+count(1)+id(4)+port(2) => obfu options at offset 29.
	if fpObfu.Bytes()[29] != 0 {
		t.Fatalf("obfu options mismatch: got=%d", fpObfu.Bytes()[29])
	}

	sp, err := BuildSearchResultPacket([]storage.File{{
		Hash: fileHash, Name: "a.bin", Size: 10, Type: "Pro", Sources: 1, Completed: 1, SourceID: 11, SourcePort: 22,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if sp.Bytes()[5] != OpSearchResult {
		t.Fatalf("opcode mismatch")
	}
}

func TestBuildSearchResultPacketCanCompress(t *testing.T) {
	fileHash := []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	files := make([]storage.File, 0, 40)
	for i := 0; i < 40; i++ {
		files = append(files, storage.File{
			Hash: fileHash, Name: "same-name-for-better-compression.bin", Size: 10, Type: "Pro",
			Sources: 1, Completed: 1, SourceID: 11, SourcePort: 22,
		})
	}
	packet, err := BuildSearchResultPacket(files)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Bytes()[5] != OpSearchResult {
		t.Fatalf("opcode mismatch")
	}
	if packet.Bytes()[0] == PrZlib {
		inflated, err := InflateZlibPayload(packet.Bytes()[6:])
		if err != nil {
			t.Fatal(err)
		}
		if len(inflated) == 0 {
			t.Fatalf("unexpected empty inflated payload")
		}
	}
}
