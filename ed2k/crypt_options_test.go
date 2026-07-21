package ed2k

import (
	"testing"

	"enode/storage"
)

// cryptOptionsFromLoginFlags maps only the three crypt capability bits and must
// ignore every other login capability (zlib, unicode, large files).
func TestCryptOptionsFromLoginFlags(t *testing.T) {
	cases := []struct {
		name  string
		flags uint32
		want  byte
	}{
		{"none", 0, 0x00},
		{"supports", FlagSupportCrypt, 0x01},
		{"requests", FlagRequestCrypt, 0x02},
		{"requires", FlagRequireCrypt, 0x04},
		{"supports+requests", FlagSupportCrypt | FlagRequestCrypt, 0x03},
		{"all three", FlagSupportCrypt | FlagRequestCrypt | FlagRequireCrypt, 0x07},
		{"only unrelated caps", FlagZlib | FlagUnicode | FlagLargeFiles, 0x00},
	}
	for _, tc := range cases {
		got := cryptOptionsFromLoginFlags(tc.flags)
		t.Logf("input: flags=0x%04x -> output: cryptOptions=0x%02x", tc.flags, got)
		if got != tc.want {
			t.Fatalf("%s: cryptOptionsFromLoginFlags(0x%04x)=0x%02x, want 0x%02x", tc.name, tc.flags, got, tc.want)
		}
	}
}

// End to end: a client advertising SUPPORT|REQUEST crypt in its login flags tag
// must surface as OP_FOUNDSOURCES_OBFU options byte 0x83 (0x01|0x02|0x80) with the
// user hash appended. This ties login parsing to the wire builder through the
// storage.Source.CryptOptions field.
func TestLoginFlagsFlowToObfuByte(t *testing.T) {
	flags := FlagSupportCrypt | FlagRequestCrypt
	tags := []Tag{{Type: TypeUint32, Code: TagFlags, Data: flags}}
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
	crypt := cryptOptionsFromLoginFlags(loginFlags(req.Tags))
	t.Logf("input: login flags tag=0x%04x -> parsed cryptOptions=0x%02x", flags, crypt)
	if crypt != 0x03 {
		t.Fatalf("parsed crypt options=0x%02x, want 0x03", crypt)
	}

	fileHash := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	userHash := []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	pkt, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{
		ID: 11, Port: 22, UserHash: userHash, CryptOptions: crypt,
	}})
	if err != nil {
		t.Fatal(err)
	}
	// protocol(1)+size(4)+opcode(1)+hash(16)+count(1)+id(4)+port(2) => options at 29.
	got := pkt.Bytes()[29]
	t.Logf("output: OP_FOUNDSOURCES_OBFU options byte=0x%02x", got)
	if got != 0x83 {
		t.Fatalf("obfu options byte=0x%02x, want 0x83 (supports|requests|hash)", got)
	}
	if h := pkt.Bytes()[30:46]; h[0] != 9 || h[15] != 9 {
		t.Fatalf("user hash not appended: %x", h)
	}
}
