package ed2k

import (
	"fmt"

	"enode/storage"
)

func ParseSearchExpr(b *Buffer) (*storage.SearchExpr, error) {
	if b == nil {
		return nil, fmt.Errorf("search buffer is nil")
	}
	return parseSearchExpr(b)
}

func parseSearchExpr(b *Buffer) (*storage.SearchExpr, error) {
	token, err := b.GetUInt8()
	if err != nil {
		return nil, err
	}

	switch token {
	case 0x01:
		s, err := b.GetString()
		if err != nil {
			return nil, err
		}
		return &storage.SearchExpr{Kind: storage.SearchText, Text: s}, nil
	case TypeString:
		s, err := b.GetString()
		if err != nil {
			return nil, err
		}
		t0, err := b.GetUInt8()
		if err != nil {
			return nil, err
		}
		t1, err := b.GetUInt16LE()
		if err != nil {
			return nil, err
		}
		typ := uint32(t0) + uint32(t1)<<8
		return &storage.SearchExpr{Kind: storage.SearchString, TagType: typ, ValueString: s}, nil
	case TypeUint32:
		v, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		typ, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		return &storage.SearchExpr{Kind: storage.SearchUInt32, TagType: typ, ValueUint: uint64(v)}, nil
	case 0x08:
		lo, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		hi, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		typ, err := b.GetUInt32LE()
		if err != nil {
			return nil, err
		}
		val := uint64(lo) + uint64(hi)<<32
		return &storage.SearchExpr{Kind: storage.SearchUInt64, TagType: typ, ValueUint: val}, nil
	case 0x00:
		op, err := b.GetUInt8()
		if err != nil {
			return nil, err
		}
		left, err := parseSearchExpr(b)
		if err != nil {
			return nil, err
		}
		right, err := parseSearchExpr(b)
		if err != nil {
			return nil, err
		}
		kind := storage.SearchAnd
		switch op {
		case 0x01:
			kind = storage.SearchOr
		case 0x02:
			kind = storage.SearchAndNot
		}
		return &storage.SearchExpr{Kind: kind, Left: left, Right: right}, nil
	default:
		return nil, fmt.Errorf("unknown search token 0x%x", token)
	}
}
