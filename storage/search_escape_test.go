package storage

import (
	"strings"
	"testing"
)

// TestEscapeLike pins L13's escaping helper: %, _ and the escape backslash itself
// are backslash-escaped so a search term matches them literally.
func TestEscapeLike(t *testing.T) {
	cases := []struct{ in, want string }{
		{`a%b_c\d`, `a\%b\_c\\d`},
		{`plain`, `plain`},
		{`100%`, `100\%`},
		{`a_b`, `a\_b`},
		{``, ``},
	}
	for _, c := range cases {
		got := escapeLike(c.in)
		t.Logf("input=%q output=%q", c.in, got)
		if got != c.want {
			t.Fatalf("escapeLike(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestBuildSearchWhereEscapesWildcards pins that a % inside a search term reaches
// MySQL as an escaped literal, not a wildcard — so the three engines agree, the
// memory and Mongo engines already treating it literally. Against the pre-fix
// build the bound argument is the raw "%a%b%".
func TestBuildSearchWhereEscapesWildcards(t *testing.T) {
	expr := &SearchExpr{Kind: SearchText, Text: "a%b"}
	sql, args := BuildSearchWhere(expr)
	t.Logf("input: text search %q", "a%b")
	t.Logf("output: sql=%q args=%v", sql, args)

	if len(args) != 1 {
		t.Fatalf("want 1 bound arg, got %d: %v", len(args), args)
	}
	got, _ := args[0].(string)
	if !strings.Contains(got, `\%`) {
		t.Fatalf("bound arg %q does not escape the %% wildcard", got)
	}
	if got != `%a\%b%` {
		t.Fatalf("bound arg = %q, want %q", got, `%a\%b%`)
	}
}
