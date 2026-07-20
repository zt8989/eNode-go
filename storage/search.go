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

// whereNode is a partially built WHERE clause. Three states matter and must not
// be conflated:
//
//	prune       — the node expresses no constraint (an unsupported tag). It is
//	              dropped and its siblings survive.
//	contradiction — a real constraint that nothing can satisfy (an all-whitespace
//	              text term). It propagates through AND, not through OR.
//	constraint  — ordinary SQL.
//
// Collapsing the first two into "" is what made a single unsupported tag
// discard the entire query, so callers got zero rows for a search that should
// have matched.
type whereNode struct {
	sql   string
	args  []any
	prune bool
}

func (n whereNode) contradiction() bool { return !n.prune && n.sql == "" }

var (
	prunedNode        = whereNode{prune: true}
	contradictionNode = whereNode{}
)

func BuildSearchWhere(expr *SearchExpr) (string, []any) {
	node := buildSearchNode(expr)
	// A tree that is entirely unsupported carries no constraint at all. Return
	// the empty clause so engines keep their existing "no results" guard rather
	// than running an unfiltered scan.
	if node.prune {
		return "", nil
	}
	return node.sql, node.args
}

func buildSearchWhere(expr *SearchExpr) (string, []any) {
	return BuildSearchWhere(expr)
}

func buildSearchNode(expr *SearchExpr) whereNode {
	if expr == nil {
		return prunedNode
	}
	switch expr.Kind {
	case SearchText:
		terms := splitTerms(expr.Text)
		if len(terms) == 0 {
			// An all-whitespace term is a real constraint that nothing meets —
			// distinct from an unsupported tag, and it must not be dropped.
			return contradictionNode
		}
		parts := make([]string, 0, len(terms))
		args := make([]any, 0, len(terms))
		for _, t := range terms {
			parts = append(parts, "s.name LIKE ?")
			args = append(args, "%"+t+"%")
		}
		return whereNode{sql: "(" + strings.Join(parts, " AND ") + ")", args: args}
	case SearchString:
		if expr.TagType == searchTypeText {
			return buildSearchNode(&SearchExpr{Kind: SearchText, Text: expr.ValueString})
		}
		switch expr.TagType {
		case searchTypeFileType:
			return whereNode{sql: "(s.type = ?)", args: []any{expr.ValueString}}
		case searchTypeExt:
			return whereNode{sql: "(s.ext = ?)", args: []any{expr.ValueString}}
		case searchTypeCodec:
			return whereNode{sql: "(s.codec = ?)", args: []any{expr.ValueString}}
		default:
			return prunedNode
		}
	case SearchUInt32, SearchUInt64:
		val := expr.ValueUint
		switch expr.TagType {
		case searchTypeSizeGt:
			return whereNode{sql: "(f.size > ?)", args: []any{val}}
		case searchTypeSizeLt:
			return whereNode{sql: "(f.size < ?)", args: []any{val}}
		case searchTypeSources:
			return whereNode{sql: "(f.sources > ?)", args: []any{val}}
		case searchTypeBitrate:
			return whereNode{sql: "(s.bitrate > ?)", args: []any{val}}
		case searchTypeDuration:
			return whereNode{sql: "(s.length > ?)", args: []any{val}}
		case searchTypeComplete:
			return whereNode{sql: "(f.completed > ?)", args: []any{val}}
		default:
			return prunedNode
		}
	case SearchAnd, SearchOr, SearchAndNot:
		return combineWhereNodes(expr.Kind, buildSearchNode(expr.Left), buildSearchNode(expr.Right))
	default:
		return prunedNode
	}
}

func MatchSearchExpr(expr *SearchExpr, file File) bool {
	if expr == nil {
		return false
	}
	matches, prune := matchSearchExpr(expr, file)
	// A query made entirely of unsupported tags constrains nothing, so it
	// matches nothing — the same answer the SQL engines give for that tree.
	if prune {
		return false
	}
	return matches
}

// matchSearchExpr evaluates an expression against one file, returning whether
// it matched and whether the node should be pruned (carried no constraint).
//
// It mirrors buildSearchNode's rules exactly. Before this existed the memory
// engine returned plain false for an unsupported leaf, so `supported OR
// unsupported` matched here but returned nothing from MySQL and MongoDB — the
// three engines gave different answers for identical input.
func matchSearchExpr(expr *SearchExpr, file File) (matches, prune bool) {
	if expr == nil {
		return false, true
	}
	switch expr.Kind {
	case SearchText:
		terms := splitTerms(expr.Text)
		if len(terms) == 0 {
			return false, false
		}
		name := strings.ToLower(file.Name)
		for _, t := range terms {
			if !strings.Contains(name, strings.ToLower(t)) {
				return false, false
			}
		}
		return true, false
	case SearchString:
		if expr.TagType == searchTypeText {
			return matchSearchExpr(&SearchExpr{Kind: SearchText, Text: expr.ValueString}, file)
		}
		switch expr.TagType {
		case searchTypeFileType:
			return strings.EqualFold(file.Type, expr.ValueString), false
		case searchTypeExt:
			return strings.EqualFold(fileExt(file.Name), expr.ValueString), false
		case searchTypeCodec:
			return strings.EqualFold(file.Codec, expr.ValueString), false
		default:
			return false, true
		}
	case SearchUInt32, SearchUInt64:
		val := expr.ValueUint
		switch expr.TagType {
		case searchTypeSizeGt:
			return file.Size > val, false
		case searchTypeSizeLt:
			return file.Size < val, false
		case searchTypeSources:
			return uint64(file.Sources) > val, false
		case searchTypeBitrate:
			return uint64(file.Bitrate) > val, false
		case searchTypeDuration:
			return uint64(file.Runtime) > val, false
		case searchTypeComplete:
			return uint64(file.Completed) > val, false
		default:
			return false, true
		}
	case SearchAnd, SearchOr, SearchAndNot:
		leftMatch, leftPrune := matchSearchExpr(expr.Left, file)
		rightMatch, rightPrune := matchSearchExpr(expr.Right, file)

		if expr.Kind == SearchAndNot {
			if rightPrune {
				return leftMatch, leftPrune
			}
			if leftPrune {
				return false, true
			}
			return leftMatch && !rightMatch, false
		}
		if leftPrune {
			return rightMatch, rightPrune
		}
		if rightPrune {
			return leftMatch, false
		}
		if expr.Kind == SearchOr {
			return leftMatch || rightMatch, false
		}
		return leftMatch && rightMatch, false
	default:
		return false, true
	}
}

// combineWhereNodes joins two operands, dropping any that carry no constraint.
//
// Substituting a truth value for a pruned operand would be wrong: neutral-true
// under AND NOT turns `A AND NOT <unsupported>` into `A AND NOT TRUE`, which is
// empty. Removing the node from the tree is a different operation, and it is
// the one that preserves the user's intent.
func combineWhereNodes(kind SearchKind, left, right whereNode) whereNode {
	if kind == SearchAndNot {
		// Nothing meaningful to negate: keep the positive side as-is. That covers
		// both an unsupported right operand and NOT(matches-nothing), which is
		// unconstrained rather than universally true.
		if right.prune || right.contradiction() {
			return left
		}
		// Dropping the left operand would leave a bare NOT, which matches very
		// nearly the whole table — far wider than anything the client asked for.
		if left.prune {
			return prunedNode
		}
		if left.contradiction() {
			return contradictionNode
		}
		return joinWhereNodes(left, right, " AND NOT ")
	}

	if left.prune {
		return right
	}
	if right.prune {
		return left
	}

	if kind == SearchOr {
		// A contradiction is absorbed by the other branch rather than poisoning
		// it — this is where the memory engine and the SQL engines used to
		// disagree on identical input.
		if left.contradiction() {
			return right
		}
		if right.contradiction() {
			return left
		}
		return joinWhereNodes(left, right, " OR ")
	}

	if left.contradiction() || right.contradiction() {
		return contradictionNode
	}
	return joinWhereNodes(left, right, " AND ")
}

func joinWhereNodes(left, right whereNode, op string) whereNode {
	args := make([]any, 0, len(left.args)+len(right.args))
	args = append(args, left.args...)
	args = append(args, right.args...)
	return whereNode{sql: "(" + left.sql + op + right.sql + ")", args: args}
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
