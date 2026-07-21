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
	if fp.Bytes()[27] != 22 || fp.Bytes()[28] != 0 {
		t.Fatalf("normal port mismatch: got=%02x%02x", fp.Bytes()[27], fp.Bytes()[28])
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
	// ID 11 is a LowID. The obfu variant used to overwrite its port with a
	// fabricated 0xFFFF; the port must be the real one, byte-identical to what
	// the non-obfuscated packet carries.
	if fpObfu.Bytes()[27] != 22 || fpObfu.Bytes()[28] != 0 {
		t.Fatalf("obfu lowid port mismatch: got=%02x%02x want=1600",
			fpObfu.Bytes()[27], fpObfu.Bytes()[28])
	}
	if fpObfu.Bytes()[27] != fp.Bytes()[27] || fpObfu.Bytes()[28] != fp.Bytes()[28] {
		t.Fatalf("obfu and non-obfu ports differ: obfu=%02x%02x normal=%02x%02x",
			fpObfu.Bytes()[27], fpObfu.Bytes()[28], fp.Bytes()[27], fp.Bytes()[28])
	}
	// N2: the user hash is tied to crypt capability. A source that carries a hash
	// but advertised no crypt options must yield options byte 0x00 and NO hash — the
	// old code emitted 0x80 + hash regardless of crypt, which is what this asserts
	// against.
	fpHashNoCrypt, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{
		ID: 11, Port: 22, UserHash: []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: obfu source hash-present crypt=0x00 -> options=0x%02x size=%d",
		fpHashNoCrypt.Bytes()[29], len(fpHashNoCrypt.Bytes()))
	if len(fpHashNoCrypt.Bytes()) != len(fpObfu.Bytes()) {
		t.Fatalf("hash-without-crypt should carry no hash: size=%d want=%d", len(fpHashNoCrypt.Bytes()), len(fpObfu.Bytes()))
	}
	if fpHashNoCrypt.Bytes()[29] != 0x00 {
		t.Fatalf("hash-without-crypt options mismatch: got=0x%02x want=0x00", fpHashNoCrypt.Bytes()[29])
	}

	// A crypt-capable source (0x01 supports) with a hash: options 0x81, hash follows.
	fpObfuHash, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{
		ID: 11, Port: 22, CryptOptions: 0x01,
		UserHash: []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: obfu source crypt=0x01 hash-present -> options=0x%02x size=%d",
		fpObfuHash.Bytes()[29], len(fpObfuHash.Bytes()))
	if len(fpObfuHash.Bytes()) != len(fpObfu.Bytes())+16 {
		t.Fatalf("obfu-hash packet size mismatch: nohash=%d hash=%d", len(fpObfu.Bytes()), len(fpObfuHash.Bytes()))
	}
	if fpObfuHash.Bytes()[29] != 0x81 {
		t.Fatalf("obfu-hash options mismatch: got=0x%02x want=0x81", fpObfuHash.Bytes()[29])
	}
	if got := fpObfuHash.Bytes()[30:46]; len(got) != 16 || got[0] != 9 || got[15] != 9 {
		t.Fatalf("obfu-hash userhash mismatch: %x", got)
	}

	// requests-crypt (0x02) but no hash available: options 0x02, no hash appended.
	fpReqNoHash, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{
		ID: 11, Port: 22, CryptOptions: 0x02,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: obfu source crypt=0x02 no-hash -> options=0x%02x size=%d",
		fpReqNoHash.Bytes()[29], len(fpReqNoHash.Bytes()))
	if len(fpReqNoHash.Bytes()) != len(fpObfu.Bytes()) {
		t.Fatalf("crypt-without-hash size mismatch: got=%d want=%d", len(fpReqNoHash.Bytes()), len(fpObfu.Bytes()))
	}
	if fpReqNoHash.Bytes()[29] != 0x02 {
		t.Fatalf("crypt-without-hash options mismatch: got=0x%02x want=0x02", fpReqNoHash.Bytes()[29])
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
