package ed2k

import (
	"fmt"

	"enode/storage"
)

// MaxSearchExprDepth bounds how deeply a boolean search expression may nest.
// Each 0x00 token costs 2 bytes and recurses twice, so without a limit a peer
// can drive the parser past Go's 1 GB stack ceiling — which is a runtime throw,
// not a panic, so no recover() could contain it.
//
// 24 matches eMule, which uses the same value when *building* an expression:
// srchybrid/kademlia/net/KademliaUDPListener.cpp:889 and
// src/core/kademlia/KadUDPListener.cpp:525. The C++ comment notes the parse
// limit has to match the generation limit, so a lower value here would reject
// queries real clients legitimately emit.
const MaxSearchExprDepth = 24

func ParseSearchExpr(b *Buffer) (*storage.SearchExpr, error) {
	if b == nil {
		return nil, fmt.Errorf("search buffer is nil")
	}
	return parseSearchExpr(b, 0)
}

func parseSearchExpr(b *Buffer, depth int) (*storage.SearchExpr, error) {
	if depth >= MaxSearchExprDepth {
		return nil, fmt.Errorf("search expression nested deeper than %d levels", MaxSearchExprDepth)
	}
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
		// Only the boolean token recurses, so incrementing here counts nesting
		// levels rather than nodes — matching how eMule seeds and advances
		// iLevel in CreateSearchExpressionTree.
		left, err := parseSearchExpr(b, depth+1)
		if err != nil {
			return nil, err
		}
		right, err := parseSearchExpr(b, depth+1)
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
