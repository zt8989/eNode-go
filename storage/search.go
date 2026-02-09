package storage

import (
	"path/filepath"
	"strings"
)

type SearchKind int

const (
	SearchText SearchKind = iota
	SearchAnd
	SearchOr
	SearchAndNot
	SearchString
	SearchUInt32
	SearchUInt64
)

type SearchExpr struct {
	Kind        SearchKind
	Text        string
	TagType     uint32
	ValueString string
	ValueUint   uint64
	Left        *SearchExpr
	Right       *SearchExpr
}

const (
	searchTypeText     uint32 = 0x0000ff
	searchTypeAnd      uint32 = 0x000000
	searchTypeOr       uint32 = 0x000001
	searchTypeAndNot   uint32 = 0x000002
	searchTypeFileType uint32 = 0x030001
	searchTypeExt      uint32 = 0x040001
	searchTypeCodec    uint32 = 0xd50001
	searchTypeSizeGt   uint32 = 0x02000101
	searchTypeSizeLt   uint32 = 0x02000102
	searchTypeSources  uint32 = 0x15000101
	searchTypeBitrate  uint32 = 0xd4000101
	searchTypeDuration uint32 = 0xd3000101
	searchTypeComplete uint32 = 0x30000101
)

func BuildSearchWhere(expr *SearchExpr) (string, []any) {
	return buildSearchWhere(expr)
}

func buildSearchWhere(expr *SearchExpr) (string, []any) {
	if expr == nil {
		return "", nil
	}
	switch expr.Kind {
	case SearchText:
		terms := splitTerms(expr.Text)
		if len(terms) == 0 {
			return "", nil
		}
		parts := make([]string, 0, len(terms))
		args := make([]any, 0, len(terms))
		for _, t := range terms {
			parts = append(parts, "s.name LIKE ?")
			args = append(args, "%"+t+"%")
		}
		return "(" + strings.Join(parts, " AND ") + ")", args
	case SearchString:
		if expr.TagType == searchTypeText {
			return BuildSearchWhere(&SearchExpr{Kind: SearchText, Text: expr.ValueString})
		}
		switch expr.TagType {
		case searchTypeFileType:
			return "(s.type = ?)", []any{expr.ValueString}
		case searchTypeExt:
			return "(s.ext = ?)", []any{expr.ValueString}
		case searchTypeCodec:
			return "(s.codec = ?)", []any{expr.ValueString}
		default:
			return "", nil
		}
	case SearchUInt32, SearchUInt64:
		val := expr.ValueUint
		switch expr.TagType {
		case searchTypeSizeGt:
			return "(f.size > ?)", []any{val}
		case searchTypeSizeLt:
			return "(f.size < ?)", []any{val}
		case searchTypeSources:
			return "(f.sources > ?)", []any{val}
		case searchTypeBitrate:
			return "(s.bitrate > ?)", []any{val}
		case searchTypeDuration:
			return "(s.length > ?)", []any{val}
		case searchTypeComplete:
			return "(f.completed > ?)", []any{val}
		default:
			return "", nil
		}
	case SearchAnd, SearchOr, SearchAndNot:
		lw, la := buildSearchWhere(expr.Left)
		rw, ra := buildSearchWhere(expr.Right)
		if lw == "" || rw == "" {
			return "", nil
		}
		var op string
		switch expr.Kind {
		case SearchOr:
			op = " OR "
		case SearchAndNot:
			op = " AND NOT "
		default:
			op = " AND "
		}
		return "(" + lw + op + rw + ")", append(la, ra...)
	default:
		return "", nil
	}
}

func MatchSearchExpr(expr *SearchExpr, file File) bool {
	if expr == nil {
		return false
	}
	switch expr.Kind {
	case SearchText:
		terms := splitTerms(expr.Text)
		if len(terms) == 0 {
			return false
		}
		name := strings.ToLower(file.Name)
		for _, t := range terms {
			if !strings.Contains(name, strings.ToLower(t)) {
				return false
			}
		}
		return true
	case SearchString:
		if expr.TagType == searchTypeText {
			return MatchSearchExpr(&SearchExpr{Kind: SearchText, Text: expr.ValueString}, file)
		}
		switch expr.TagType {
		case searchTypeFileType:
			return strings.EqualFold(file.Type, expr.ValueString)
		case searchTypeExt:
			return strings.EqualFold(fileExt(file.Name), expr.ValueString)
		case searchTypeCodec:
			return strings.EqualFold(file.Codec, expr.ValueString)
		default:
			return false
		}
	case SearchUInt32, SearchUInt64:
		val := expr.ValueUint
		switch expr.TagType {
		case searchTypeSizeGt:
			return file.Size > val
		case searchTypeSizeLt:
			return file.Size < val
		case searchTypeSources:
			return uint64(file.Sources) > val
		case searchTypeBitrate:
			return uint64(file.Bitrate) > val
		case searchTypeDuration:
			return uint64(file.Runtime) > val
		case searchTypeComplete:
			return uint64(file.Completed) > val
		default:
			return false
		}
	case SearchAnd:
		return MatchSearchExpr(expr.Left, file) && MatchSearchExpr(expr.Right, file)
	case SearchOr:
		return MatchSearchExpr(expr.Left, file) || MatchSearchExpr(expr.Right, file)
	case SearchAndNot:
		return MatchSearchExpr(expr.Left, file) && !MatchSearchExpr(expr.Right, file)
	default:
		return false
	}
}

func splitTerms(text string) []string {
	return strings.Fields(strings.TrimSpace(text))
}

func fileExt(name string) string {
	ext := filepath.Ext(name)
	if ext == "" {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(ext, "."))
}
