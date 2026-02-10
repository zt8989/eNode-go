package ed2k

import (
	"bytes"
	"errors"
	"testing"
)

func TestBufferReadWritePrimitives(t *testing.T) {
	b := NewBuffer(64)
	if err := b.PutUInt8(0x7a); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt16LE(0x1337); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt32LE(0xdeadbeef); err != nil {
		t.Fatal(err)
	}
	if err := b.PutString("abc"); err != nil {
		t.Fatal(err)
	}
	hash := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if err := b.PutHash(hash); err != nil {
		t.Fatal(err)
	}

	b.Pos(0)
	u8, err := b.GetUInt8()
	if err != nil {
		t.Fatal(err)
	}
	if u8 != 0x7a {
		t.Fatalf("u8 mismatch: got 0x%x", u8)
	}

	u16, err := b.GetUInt16LE()
	if err != nil {
		t.Fatal(err)
	}
	if u16 != 0x1337 {
		t.Fatalf("u16 mismatch: got 0x%x", u16)
	}

	u32, err := b.GetUInt32LE()
	if err != nil {
		t.Fatal(err)
	}
	if u32 != 0xdeadbeef {
		t.Fatalf("u32 mismatch: got 0x%x", u32)
	}

	s, err := b.GetString()
	if err != nil {
		t.Fatal(err)
	}
	if s != "abc" {
		t.Fatalf("string mismatch: got %q", s)
	}

	gotHash := b.Get(16)
	if !bytes.Equal(gotHash, hash) {
		t.Fatalf("hash mismatch: got %v", gotHash)
	}
}

func TestTagsRoundTrip(t *testing.T) {
	tags := []Tag{
		{Type: TypeString, Code: TagName, Data: "file.iso"},
		{Type: TypeUint32, Code: TagSize, Data: uint32(1234)},
		{Type: TypeUint16, Code: TagPort, Data: uint16(4662)},
		{Type: TypeUint8, Code: TagFlags, Data: uint8(1)},
	}
	l, err := TagsLength(tags)
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuffer(l)
	if err := b.PutTags(tags); err != nil {
		t.Fatal(err)
	}

	b.Pos(0)
	parsed, err := b.GetTags()
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 4 {
		t.Fatalf("parsed tags count mismatch: got %d", len(parsed))
	}
	if parsed[0].Name != "name" || parsed[0].Value.(string) != "file.iso" {
		t.Fatalf("name tag mismatch: %#v", parsed[0])
	}
	if parsed[1].Name != "size" || parsed[1].Value.(uint32) != 1234 {
		t.Fatalf("size tag mismatch: %#v", parsed[1])
	}
	if parsed[2].Name != "port2" || parsed[2].Value.(uint16) != 4662 {
		t.Fatalf("port tag mismatch: %#v", parsed[2])
	}
	if parsed[3].Name != "flags" || parsed[3].Value.(uint8) != 1 {
		t.Fatalf("flags tag mismatch: %#v", parsed[3])
	}
}

func TestGetFileList(t *testing.T) {
	fileTags := []Tag{
		{Type: TypeString, Code: TagName, Data: "movie.mkv"},
		{Type: TypeUint32, Code: TagSize, Data: uint32(1)},
		{Type: TypeUint32, Code: TagSizeHi, Data: uint32(1)},
	}
	tagLen, err := TagsLength(fileTags)
	if err != nil {
		t.Fatal(err)
	}

	total := 4 + 16 + 4 + 2 + tagLen
	b := NewBuffer(total)
	if err := b.PutUInt32LE(1); err != nil {
		t.Fatal(err)
	}
	hash := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	if err := b.PutHash(hash); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt32LE(ValPartialID); err != nil {
		t.Fatal(err)
	}
	if err := b.PutUInt16LE(ValPartialPort); err != nil {
		t.Fatal(err)
	}
	if err := b.PutTags(fileTags); err != nil {
		t.Fatal(err)
	}

	b.Pos(0)
	files, err := b.GetFileList()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files count mismatch: got %d", len(files))
	}
	f := files[0]
	if f.Complete {
		t.Fatalf("expected partial file")
	}
	if f.Tags["name"].(string) != "movie.mkv" {
		t.Fatalf("name mismatch: %#v", f.Tags["name"])
	}
	if f.Size != 0x100000001 {
		t.Fatalf("size mismatch: got %d", f.Size)
	}
}

func TestGetTagErrorContainsContext(t *testing.T) {
	// malformed long tag: type=TypeUint32, name-len=2 (expected 1)
	b := NewBufferFromBytes([]byte{
		TypeUint32, 0x02, 0x00, 'x', 'y', 0x11, 0x22, 0x33, 0x44,
	})
	_, err := b.GetTag()
	if err == nil {
		t.Fatal("expected error")
	}
	var tagErr *TagDecodeError
	if !errors.As(err, &tagErr) {
		t.Fatalf("expected TagDecodeError, got %T (%v)", err, err)
	}
	if tagErr.Stage != "name-len-ne-1" {
		t.Fatalf("unexpected stage: %s", tagErr.Stage)
	}
}

func TestGetTagShortFormatUint16(t *testing.T) {
	// 0x88 => short format + TypeUint16, next byte is code.
	b := NewBufferFromBytes([]byte{
		0x88, TagPort, 0x36, 0x12,
	})
	tag, err := b.GetTag()
	if err != nil {
		t.Fatal(err)
	}
	if tag.Name != "port2" {
		t.Fatalf("name mismatch: %s", tag.Name)
	}
	v, ok := tag.Value.(uint16)
	if !ok {
		t.Fatalf("value type mismatch: %T", tag.Value)
	}
	if v != 0x1236 {
		t.Fatalf("value mismatch: %d", v)
	}
}
