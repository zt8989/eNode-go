package storage

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func textExpr(term string) *SearchExpr {
	return &SearchExpr{Kind: SearchText, Text: term}
}

func typeExpr(t string) *SearchExpr {
	return &SearchExpr{Kind: SearchString, TagType: searchTypeFileType, ValueString: t}
}

// TestHoistTextLeaf pins which expression shapes may use a $text stage. MongoDB
// requires $text to be the first pipeline stage and forbids it inside $or/$nor,
// so only a single text leaf reachable through conjunctions can be hoisted.
func TestHoistTextLeaf(t *testing.T) {
	cases := []struct {
		name       string
		expr       *SearchExpr
		wantHoist  bool
		wantSearch string
		wantRest   bool // whether a remaining expression is expected
	}{
		{
			name:       "bare text leaf",
			expr:       textExpr("movie"),
			wantHoist:  true,
			wantSearch: `"movie"`,
			wantRest:   false,
		},
		{
			name:       "multiple terms are quoted so they AND",
			expr:       textExpr("big movie"),
			wantHoist:  true,
			wantSearch: `"big" "movie"`,
			wantRest:   false,
		},
		{
			name:       "text AND type",
			expr:       &SearchExpr{Kind: SearchAnd, Left: textExpr("movie"), Right: typeExpr("Video")},
			wantHoist:  true,
			wantSearch: `"movie"`,
			wantRest:   true,
		},
		{
			name:       "text on the right of AND",
			expr:       &SearchExpr{Kind: SearchAnd, Left: typeExpr("Video"), Right: textExpr("movie")},
			wantHoist:  true,
			wantSearch: `"movie"`,
			wantRest:   true,
		},
		{
			name:      "text under OR cannot be hoisted",
			expr:      &SearchExpr{Kind: SearchOr, Left: textExpr("movie"), Right: typeExpr("Video")},
			wantHoist: false,
		},
		{
			name:      "two text leaves cannot be hoisted",
			expr:      &SearchExpr{Kind: SearchAnd, Left: textExpr("movie"), Right: textExpr("hd")},
			wantHoist: false,
		},
		{
			name:      "text on the negated side cannot be hoisted",
			expr:      &SearchExpr{Kind: SearchAndNot, Left: typeExpr("Video"), Right: textExpr("cam")},
			wantHoist: false,
		},
		{
			name:       "text on the positive side of AND NOT",
			expr:       &SearchExpr{Kind: SearchAndNot, Left: textExpr("movie"), Right: typeExpr("Pro")},
			wantHoist:  false, // removing it would leave a bare negation
			wantSearch: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			search, rest, hoisted := hoistTextLeaf(tc.expr)
			t.Logf("input: %s", describeExpr(tc.expr))
			t.Logf("output: hoisted=%v search=%q rest=%s", hoisted, search, describeExpr(rest))

			if hoisted != tc.wantHoist {
				t.Fatalf("hoisted mismatch: got %v, want %v", hoisted, tc.wantHoist)
			}
			if !tc.wantHoist {
				return
			}
			if search != tc.wantSearch {
				t.Fatalf("search mismatch: got %q, want %q", search, tc.wantSearch)
			}
			if (rest != nil) != tc.wantRest {
				t.Fatalf("rest mismatch: got %v, want non-nil=%v", describeExpr(rest), tc.wantRest)
			}
			// The hoisted leaf must be gone, or it would be applied twice.
			if n := countTextLeaves(rest); n != 0 {
				t.Fatalf("rest still contains %d text leaf/leaves", n)
			}
		})
	}
}

// TestMongoSourceConjunctFilterNeverFatal covers the pushdown pre-filter. It is
// an optimization, so an expression it cannot handle must yield "no prefilter",
// never an error that discards the whole query.
func TestMongoSourceConjunctFilterNeverFatal(t *testing.T) {
	cases := []struct {
		name string
		expr *SearchExpr
	}{
		{"or", &SearchExpr{Kind: SearchOr, Left: typeExpr("Video"), Right: typeExpr("Audio")}},
		{"and not", &SearchExpr{Kind: SearchAndNot, Left: typeExpr("Video"), Right: typeExpr("Audio")}},
		{"nested or inside and", &SearchExpr{
			Kind:  SearchAnd,
			Left:  typeExpr("Video"),
			Right: &SearchExpr{Kind: SearchOr, Left: typeExpr("Audio"), Right: typeExpr("Doc")},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input: %s", describeExpr(tc.expr))
			got := mongoSourceConjunctFilter(tc.expr)
			t.Logf("output: prefilter=%v", got)
			// Only requirement: it returns without signalling a fatal condition.
			// A nil prefilter simply means the full $match does all the work.
		})
	}
}

// TestMongoFilterHandlesOrAndNot verifies the complete filter is built for the
// expression shapes an eMule client routinely sends, including the "-word"
// exclusion that produces SearchAndNot.
func TestMongoFilterHandlesOrAndNot(t *testing.T) {
	cases := []struct {
		name string
		expr *SearchExpr
	}{
		{"text", textExpr("movie")},
		{"or", &SearchExpr{Kind: SearchOr, Left: textExpr("movie"), Right: textExpr("film")}},
		{"and not", &SearchExpr{Kind: SearchAndNot, Left: textExpr("movie"), Right: textExpr("cam")}},
		{"text and type", &SearchExpr{Kind: SearchAnd, Left: textExpr("movie"), Right: typeExpr("Video")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input: %s", describeExpr(tc.expr))
			filter, needsFile := mongoFilter(tc.expr)
			t.Logf("output: filter=%v needsFile=%v", filter, needsFile)

			if filter == nil {
				t.Fatalf("filter is nil: this shape would return zero results")
			}
			if containsTextOperator(filter) {
				t.Fatalf("filter contains $text: it cannot appear outside the first stage or inside $or/$nor: %v", filter)
			}
		})
	}
}

// containsTextOperator reports whether a $text operator appears anywhere in a
// filter document.
func containsTextOperator(v any) bool {
	switch t := v.(type) {
	case bson.M:
		for k, sub := range t {
			if k == "$text" {
				return true
			}
			if containsTextOperator(sub) {
				return true
			}
		}
	case []bson.M:
		for _, sub := range t {
			if containsTextOperator(sub) {
				return true
			}
		}
	}
	return false
}

func describeExpr(expr *SearchExpr) string {
	if expr == nil {
		return "<nil>"
	}
	switch expr.Kind {
	case SearchText:
		return "text(" + expr.Text + ")"
	case SearchString:
		return "str(" + expr.ValueString + ")"
	case SearchAnd:
		return "(" + describeExpr(expr.Left) + " AND " + describeExpr(expr.Right) + ")"
	case SearchOr:
		return "(" + describeExpr(expr.Left) + " OR " + describeExpr(expr.Right) + ")"
	case SearchAndNot:
		return "(" + describeExpr(expr.Left) + " ANDNOT " + describeExpr(expr.Right) + ")"
	default:
		return "expr"
	}
}
