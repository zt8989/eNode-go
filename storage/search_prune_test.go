package storage

import (
	"testing"
)

// unsupportedTag is a tag type no engine recognises. Real clients do send tags
// the server has no column for, which is the whole point of this behaviour.
const unsupportedTag uint32 = 0xdeadbeef

func unsupportedLeaf() *SearchExpr {
	return &SearchExpr{Kind: SearchString, TagType: unsupportedTag, ValueString: "x"}
}

func textLeaf(s string) *SearchExpr {
	return &SearchExpr{Kind: SearchText, Text: s}
}

// One unsupported leaf used to poison the whole tree: buildSearchWhere returned
// "" for it, and the AND/OR combiner propagated that "" upward through every
// ancestor, discarding the sibling subtrees too. The engines then saw an empty
// WHERE and returned no rows — a silent zero-result for a query that should
// have matched.
func TestBuildSearchWhereDropsUnsupportedLeaf(t *testing.T) {
	cases := []struct {
		name    string
		expr    *SearchExpr
		wantSQL string
	}{
		{
			"AND keeps the supported side",
			&SearchExpr{Kind: SearchAnd, Left: textLeaf("foo"), Right: unsupportedLeaf()},
			"(s.name LIKE ?)",
		},
		{
			"AND keeps the supported side when it is on the right",
			&SearchExpr{Kind: SearchAnd, Left: unsupportedLeaf(), Right: textLeaf("foo")},
			"(s.name LIKE ?)",
		},
		{
			"OR keeps the supported side",
			&SearchExpr{Kind: SearchOr, Left: textLeaf("foo"), Right: unsupportedLeaf()},
			"(s.name LIKE ?)",
		},
		{
			"AND NOT with an unsupported right keeps the positive side",
			&SearchExpr{Kind: SearchAndNot, Left: textLeaf("foo"), Right: unsupportedLeaf()},
			"(s.name LIKE ?)",
		},
		{
			// A bare NOT would match nearly the whole table — far wider than the
			// client asked for, so the node goes rather than the operand.
			"AND NOT with an unsupported left drops the whole node",
			&SearchExpr{Kind: SearchAndNot, Left: unsupportedLeaf(), Right: textLeaf("foo")},
			"",
		},
		{
			"a wholly unsupported tree yields no clause",
			&SearchExpr{Kind: SearchAnd, Left: unsupportedLeaf(), Right: unsupportedLeaf()},
			"",
		},
		{
			"both sides supported still combine",
			&SearchExpr{Kind: SearchAnd, Left: textLeaf("foo"), Right: &SearchExpr{Kind: SearchString, TagType: searchTypeExt, ValueString: "avi"}},
			"((s.name LIKE ?) AND (s.ext = ?))",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql, args := BuildSearchWhere(tc.expr)
			t.Logf("output: sql=%q args=%v", sql, args)
			if sql != tc.wantSQL {
				t.Fatalf("got %q, want %q", sql, tc.wantSQL)
			}
			// Placeholders and arguments must stay in step or the query is
			// malformed at execution time rather than at build time.
			placeholders := 0
			for _, c := range sql {
				if c == '?' {
					placeholders++
				}
			}
			if placeholders != len(args) {
				t.Fatalf("%d placeholders but %d args: %q %v", placeholders, len(args), sql, args)
			}
		})
	}
}

// An all-whitespace text term is a real constraint that nothing satisfies. It
// must not be confused with an unsupported tag: dropping it would widen the
// query instead of narrowing it.
func TestBuildSearchWhereKeepsContradictionDistinctFromPrune(t *testing.T) {
	blank := textLeaf("   ")

	andExpr := &SearchExpr{Kind: SearchAnd, Left: textLeaf("foo"), Right: blank}
	sql, _ := BuildSearchWhere(andExpr)
	t.Logf("output: `foo AND <blank>` -> %q", sql)
	if sql != "" {
		t.Fatalf("a contradiction under AND should match nothing, got %q", sql)
	}

	orExpr := &SearchExpr{Kind: SearchOr, Left: textLeaf("foo"), Right: blank}
	sql, args := BuildSearchWhere(orExpr)
	t.Logf("output: `foo OR <blank>` -> %q args=%v", sql, args)
	if sql != "(s.name LIKE ?)" {
		t.Fatalf("a contradiction under OR should be absorbed, got %q", sql)
	}
}

// The three engines have to agree. The memory engine previously returned plain
// false for an unsupported leaf, so `supported OR unsupported` matched here
// while MySQL and MongoDB returned nothing for the identical expression.
func TestMatchSearchExprAgreesWithSQLOnUnsupportedLeaf(t *testing.T) {
	file := File{Name: "foo.bin", Size: 1024}

	cases := []struct {
		name string
		expr *SearchExpr
		want bool
	}{
		{"AND with unsupported right", &SearchExpr{Kind: SearchAnd, Left: textLeaf("foo"), Right: unsupportedLeaf()}, true},
		{"AND with unsupported left", &SearchExpr{Kind: SearchAnd, Left: unsupportedLeaf(), Right: textLeaf("foo")}, true},
		{"OR with unsupported right", &SearchExpr{Kind: SearchOr, Left: textLeaf("foo"), Right: unsupportedLeaf()}, true},
		{"AND NOT with unsupported right", &SearchExpr{Kind: SearchAndNot, Left: textLeaf("foo"), Right: unsupportedLeaf()}, true},
		{"AND NOT with unsupported left", &SearchExpr{Kind: SearchAndNot, Left: unsupportedLeaf(), Right: textLeaf("foo")}, false},
		{"wholly unsupported", &SearchExpr{Kind: SearchAnd, Left: unsupportedLeaf(), Right: unsupportedLeaf()}, false},
		{"a non-matching term still fails", &SearchExpr{Kind: SearchAnd, Left: textLeaf("nope"), Right: unsupportedLeaf()}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchSearchExpr(tc.expr, file)
			sql, _ := BuildSearchWhere(tc.expr)
			t.Logf("input: file=%q -> output: memory=%t sqlClause=%q", file.Name, got, sql)

			if got != tc.want {
				t.Fatalf("memory engine returned %t, want %t", got, tc.want)
			}
			// Cross-check the shape: an empty clause means the SQL engines return
			// nothing, so the memory engine must not be matching either.
			if sql == "" && got {
				t.Fatal("memory engine matched a file the SQL engines would drop")
			}
		})
	}
}

// The end-to-end version of the same bug, through the default engine.
func TestMemoryEngineFindBySearchWithUnsupportedTag(t *testing.T) {
	engine := NewMemoryEngine()
	owner := ClientInfo{Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662}
	engine.Connect(owner)
	engine.AddFile(File{Hash: []byte("fedcba9876543210"), Size: 1024, Name: "foo.bin"}, owner)

	expr := &SearchExpr{Kind: SearchAnd, Left: textLeaf("foo"), Right: unsupportedLeaf()}
	files := engine.FindBySearch(expr)
	t.Logf("input: `foo AND <unsupported tag 0x%x>` -> output: %d file(s)", unsupportedTag, len(files))

	if len(files) != 1 {
		t.Fatalf("got %d files, want 1 — the unsupported leaf discarded the query", len(files))
	}
	if files[0].Name != "foo.bin" {
		t.Fatalf("unexpected file %q", files[0].Name)
	}
}
