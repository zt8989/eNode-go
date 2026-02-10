package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrOutOfBounds       = errors.New("buffer: out of bounds")
	ErrInvalidHashLength = errors.New("buffer: hash must be 16 bytes")
	ErrUnsupportedTag    = errors.New("buffer: unsupported tag type")
	ErrUnhandledTag      = errors.New("buffer: unhandled tag")
)

type Tag struct {
	Type uint8
	Code uint8
	Data any
}

type NamedTag struct {
	Name  string
	Value any
}

type FileRecord struct {
	Hash     []byte
	Complete bool
	ID       uint32
	Port     uint16
	Tags     map[string]any
	SizeLo   uint32
	SizeHi   uint32
	Size     uint64
}

type TagDecodeError struct {
	Pos     int
	Stage   string
	TagType uint8
	Code    uint8
	Err     error
}

func (e *TagDecodeError) Error() string {
	if e == nil {
		return "tag decode error"
	}
	if e.Code != 0 {
		return fmt.Sprintf("tag decode failed stage=%s pos=%d type=0x%x code=0x%x: %v",
			e.Stage, e.Pos, e.TagType, e.Code, e.Err)
	}
	return fmt.Sprintf("tag decode failed stage=%s pos=%d type=0x%x: %v",
		e.Stage, e.Pos, e.TagType, e.Err)
}

func (e *TagDecodeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type Buffer struct {
	data    []byte
	pointer int
}

func NewBuffer(size int) *Buffer {
	return &Buffer{data: make([]byte, size)}
}

func NewBufferFromBytes(data []byte) *Buffer {
	return &Buffer{data: data}
}

func (b *Buffer) Bytes() []byte {
	return b.data
}

func (b *Buffer) Pos(pos ...int) int {
	if len(pos) == 0 {
		return b.pointer
	}
	b.pointer = pos[0]
	if b.pointer < 0 {
		b.pointer = 0
	}
	if b.pointer > len(b.data) {
		b.pointer = len(b.data)
	}
	return b.pointer
}

func (b *Buffer) require(n int) error {
	if b.pointer+n > len(b.data) {
		return ErrOutOfBounds
	}
	return nil
}

func (b *Buffer) GetUInt8() (uint8, error) {
	if err := b.require(1); err != nil {
		return 0, err
	}
	v := b.data[b.pointer]
	b.pointer++
	return v, nil
}

func (b *Buffer) PutUInt8(n uint8) error {
	if err := b.require(1); err != nil {
		return err
	}
	b.data[b.pointer] = n
	b.pointer++
	return nil
}

func (b *Buffer) GetUInt16LE() (uint16, error) {
	if err := b.require(2); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint16(b.data[b.pointer:])
	b.pointer += 2
	return v, nil
}

func (b *Buffer) PutUInt16LE(n uint16) error {
	if err := b.require(2); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(b.data[b.pointer:], n)
	b.pointer += 2
	return nil
}

func (b *Buffer) GetUInt32LE() (uint32, error) {
	if err := b.require(4); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(b.data[b.pointer:])
	b.pointer += 4
	return v, nil
}

func (b *Buffer) PutUInt32LE(n uint32) error {
	if err := b.require(4); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(b.data[b.pointer:], n)
	b.pointer += 4
	return nil
}

func (b *Buffer) GetUInt64LE() (uint64, error) {
	if err := b.require(8); err != nil {
		return 0, err
	}
	lo := binary.LittleEndian.Uint32(b.data[b.pointer:])
	hi := binary.LittleEndian.Uint32(b.data[b.pointer+4:])
	b.pointer += 8
	return uint64(lo) + uint64(hi)*0x100000000, nil
}

func (b *Buffer) GetString(length ...int) (string, error) {
	l := 0
	if len(length) == 0 {
		v, err := b.GetUInt16LE()
		if err != nil {
			return "", err
		}
		l = int(v)
	} else {
		l = length[0]
	}
	data := b.Get(l)
	if data == nil && l != 0 {
		return "", ErrOutOfBounds
	}
	return string(data), nil
}

func (b *Buffer) PutString(s string) error {
	if err := b.PutUInt16LE(uint16(len([]byte(s)))); err != nil {
		return err
	}
	src := []byte(s)
	if err := b.require(len(src)); err != nil {
		return err
	}
	copy(b.data[b.pointer:], src)
	b.pointer += len(src)
	return nil
}

func (b *Buffer) PutBuffer(src []byte) {
	n := copy(b.data[b.pointer:], src)
	b.pointer += n
	if b.pointer > len(b.data) {
		b.pointer = len(b.data)
	}
}

func (b *Buffer) PutHash(hash []byte) error {
	if len(hash) != 16 {
		return ErrInvalidHashLength
	}
	b.PutBuffer(hash)
	return nil
}

func (b *Buffer) Get(length ...int) []byte {
	if len(length) > 0 && length[0] == 0 {
		return nil
	}
	if len(length) == 0 {
		out := b.data[b.pointer:]
		b.pointer = len(b.data)
		return out
	}
	end := b.pointer + length[0]
	if end > len(b.data) {
		end = len(b.data)
	}
	out := b.data[b.pointer:end]
	b.pointer = end
	return out
}

func TagsLength(tags []Tag) (int, error) {
	length := 4
	for _, t := range tags {
		length += 4
		switch t.Type {
		case TypeString:
			v, ok := t.Data.(string)
			if !ok {
				return 0, ErrUnsupportedTag
			}
			length += 2 + len([]byte(v))
		case TypeUint8:
			length += 1
		case TypeUint16:
			length += 2
		case TypeUint32:
			length += 4
		default:
			return 0, fmt.Errorf("%w: 0x%x", ErrUnsupportedTag, t.Type)
		}
	}
	return length, nil
}

func (b *Buffer) PutTag(tag Tag) error {
	if err := b.PutUInt8(tag.Type); err != nil {
		return err
	}
	if err := b.PutUInt16LE(1); err != nil {
		return err
	}
	if err := b.PutUInt8(tag.Code); err != nil {
		return err
	}

	switch tag.Type {
	case TypeString:
		v, ok := tag.Data.(string)
		if !ok {
			return ErrUnsupportedTag
		}
		return b.PutString(v)
	case TypeUint8:
		switch v := tag.Data.(type) {
		case uint8:
			return b.PutUInt8(v)
		case int:
			return b.PutUInt8(uint8(v))
		default:
			return ErrUnsupportedTag
		}
	case TypeUint16:
		switch v := tag.Data.(type) {
		case uint16:
			return b.PutUInt16LE(v)
		case int:
			return b.PutUInt16LE(uint16(v))
		default:
			return ErrUnsupportedTag
		}
	case TypeUint32:
		switch v := tag.Data.(type) {
		case uint32:
			return b.PutUInt32LE(v)
		case int:
			return b.PutUInt32LE(uint32(v))
		default:
			return ErrUnsupportedTag
		}
	default:
		return fmt.Errorf("%w: 0x%x", ErrUnsupportedTag, tag.Type)
	}
}

func (b *Buffer) PutTags(tags []Tag) error {
	if err := b.PutUInt32LE(uint32(len(tags))); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := b.PutTag(tag); err != nil {
			return err
		}
	}
	return nil
}

func (b *Buffer) GetTagValue(typ uint8) (any, error) {
	switch typ {
	case TypeString:
		return b.GetString()
	case TypeUint8:
		return b.GetUInt8()
	case TypeUint16:
		return b.GetUInt16LE()
	case TypeUint32:
		return b.GetUInt32LE()
	default:
		return nil, fmt.Errorf("%w: 0x%x", ErrUnsupportedTag, typ)
	}
}

func tagName(code uint8) string {
	switch code {
	case TagName:
		return "name"
	case TagSize:
		return "size"
	case TagSizeHi:
		return "sizehi"
	case TagType:
		return "type"
	case TagFormat:
		return "format"
	case TagVersion:
		return "version"
	case TagPort:
		return "port2"
	case TagSources:
		return "sources"
	case TagMuleVersion:
		return "muleversion"
	case TagFlags:
		return "flags"
	case TagRating:
		return "rating"
	case TagMediaArtist:
		return "artist"
	case TagMediaAlbum:
		return "album"
	case TagMediaTitle:
		return "title"
	case TagMediaLength:
		return "length"
	case TagMediaBitrate:
		return "bitrate"
	case TagMediaCodec:
		return "codec"
	case TagSearchTree:
		return "searchtree"
	case TagEmuleUDPPorts:
		return "udpports"
	case TagEmuleOptions1:
		return "options1"
	case TagEmuleOptions2:
		return "options2"
	default:
		return fmt.Sprintf("0x%x", code)
	}
}

func (b *Buffer) GetTag() (NamedTag, error) {
	startPos := b.Pos()
	tagType, err := b.GetUInt8()
	if err != nil {
		return NamedTag{}, err
	}
	origTagType := tagType
	shortFormat := false

	var code uint8
	var value any

	if tagType&0x80 != 0 {
		shortFormat = true
		c, err := b.GetUInt8()
		if err != nil {
			return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-short-code", TagType: origTagType, Err: err}
		}
		code = c
		tagType &= 0x7f
		if tagType >= 0x10 {
			strLen := int(tagType - 0x10)
			tagType = TypeString
			s, err := b.GetString(strLen)
			if err != nil {
				return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-short-string", TagType: origTagType, Code: code, Err: err}
			}
			value = s
		}
	}

	if value == nil {
		if !shortFormat {
			l, err := b.GetUInt16LE()
			if err != nil {
				return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-name-len", TagType: origTagType, Err: err}
			}
			if l != 1 {
				return NamedTag{}, &TagDecodeError{
					Pos:     startPos,
					Stage:   "name-len-ne-1",
					TagType: origTagType,
					Err:     fmt.Errorf("%w: name-len=%d", ErrUnhandledTag, l),
				}
			}
			c, err := b.GetUInt8()
			if err != nil {
				return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-name-code", TagType: origTagType, Err: err}
			}
			code = c
		}
		v, err := b.GetTagValue(tagType)
		if err != nil {
			return NamedTag{}, &TagDecodeError{Pos: startPos, Stage: "read-value", TagType: origTagType, Code: code, Err: err}
		}
		value = v
	}

	return NamedTag{Name: tagName(code), Value: value}, nil
}

func (b *Buffer) GetTags() ([]NamedTag, error) {
	startPos := b.Pos()
	count, err := b.GetUInt32LE()
	if err != nil {
		return nil, err
	}
	tags := make([]NamedTag, 0, count)
	for i := uint32(0); i < count; i++ {
		tag, err := b.GetTag()
		if err != nil {
			return nil, fmt.Errorf("tags decode failed start=%d idx=%d: %w", startPos, i, err)
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

func (b *Buffer) GetFileList() ([]FileRecord, error) {
	count, err := b.GetUInt32LE()
	if err != nil {
		return nil, err
	}
	files := make([]FileRecord, 0, count)
	for i := uint32(0); i < count; i++ {
		hash := append([]byte(nil), b.Get(16)...)
		if len(hash) != 16 {
			return nil, ErrOutOfBounds
		}
		id, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			return nil, err
		}
		tags, err := b.GetTags()
		if err != nil {
			return nil, fmt.Errorf("filelist decode failed file-idx=%d hash=%x id=%d port=%d: %w", i, hash, id, port, err)
		}
		record := FileRecord{
			Hash:     hash,
			Complete: true,
			ID:       id,
			Port:     port,
			Tags:     make(map[string]any, len(tags)),
		}
		for _, t := range tags {
			record.Tags[t.Name] = t.Value
		}
		if id == ValPartialID && port == ValPartialPort {
			record.Complete = false
		} else if id == ValCompleteID && port == ValCompletePort {
			record.Complete = true
		}
		if v, ok := record.Tags["size"].(uint32); ok {
			record.SizeLo = v
			record.Size = uint64(v)
		}
		if v, ok := record.Tags["sizehi"].(uint32); ok {
			record.SizeHi = v
			record.Size += uint64(v) * 0x100000000
		}
		files = append(files, record)
	}
	return files, nil
}
