package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"enode/tests"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// startMySQL brings up mysql:8.0 with the schema applied and returns a ready
// engine. 8.0 matters: ONLY_FULL_GROUP_BY and STRICT_TRANS_TABLES are both on by
// default there, which is exactly what H5 and H8 trip over.
func startMySQL(t *testing.T, database string) (*MySQLEngine, *sql.DB) {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "8.0",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=root",
			"MYSQL_DATABASE=" + database,
		},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mysql container: %v", err)
	}
	t.Cleanup(func() { _ = pool.Purge(resource) })

	port := resource.GetPort("3306/tcp")
	dsn := fmt.Sprintf("root:root@tcp(localhost:%s)/%s?parseTime=true", port, database)

	var db *sql.DB
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		var e error
		db, e = sql.Open("mysql", dsn)
		if e != nil {
			return e
		}
		return db.Ping()
	}); err != nil {
		t.Fatalf("mysql not ready: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Init creates the schema from the resolved relative path on first connect, so
	// the raw db handle above stays for the direct assertions these tests make.
	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: mustAtoi(port), User: "root", Pass: "root", Database: database,
		MaxOpenConns: 4, MaxIdleConns: 2,
		SchemaFile: tests.FixRelativeTestingPath("misc/enode.sql"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	// Confirm the modes that make these bugs reachable are actually on, so a
	// green run cannot mean "the container happened to be permissive".
	var mode string
	if err := db.QueryRow(`SELECT @@SESSION.sql_mode`).Scan(&mode); err != nil {
		t.Fatalf("read sql_mode: %v", err)
	}
	t.Logf("input: server sql_mode=%s", mode)
	if !strings.Contains(mode, "ONLY_FULL_GROUP_BY") {
		t.Fatal("ONLY_FULL_GROUP_BY is not enabled; this test could not detect H5")
	}
	if !strings.Contains(mode, "STRICT_TRANS_TABLES") {
		t.Fatal("STRICT_TRANS_TABLES is not enabled; this test could not detect H8")
	}
	return engine, db
}

// The twin of TestMongoFindBySearch that never existed for MySQL — which is why
// H5 went unnoticed. FindBySearch selects eight non-aggregated s.* columns while
// grouping by s.id_file, which ONLY_FULL_GROUP_BY rejects with ER_1055; the error
// was swallowed and the search returned no rows.
func TestMySQLFindBySearch(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")

	client := ClientInfo{ID: 401, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID

	seed := []File{
		{Hash: []byte("aaaaaaaaaaaaaaaa"), Name: "holiday movie.avi", Size: 700, Type: "Video", Completed: 1},
		{Hash: []byte("bbbbbbbbbbbbbbbb"), Name: "holiday song.mp3", Size: 800, Type: "Audio", Completed: 1},
		{Hash: []byte("cccccccccccccccc"), Name: "vacation movie.avi", Size: 900, Type: "Video", Completed: 1},
	}
	for _, f := range seed {
		engine.AddFile(f, client)
		t.Logf("input: seeded %q type=%s", f.Name, f.Type)
	}

	// A second source for one file, so id_file is genuinely non-unique in sources
	// — without this, MySQL might resolve the functional dependency and the bug
	// would not reproduce.
	second := ClientInfo{ID: 402, IPv4: 0x0100007f, Port: 4663, Hash: []byte("fedcba9876543210")}
	secondStore, err := engine.Connect(second)
	if err != nil {
		t.Fatal(err)
	}
	second.StoreID = secondStore
	engine.AddFile(seed[0], second)
	t.Logf("input: %q has two sources", seed[0].Name)

	cases := []struct {
		name  string
		expr  *SearchExpr
		want  int
		names []string
	}{
		{
			name:  "single term",
			expr:  &SearchExpr{Kind: SearchText, Text: "movie"},
			want:  2,
			names: []string{"holiday movie.avi", "vacation movie.avi"},
		},
		{
			name: "term AND type",
			expr: &SearchExpr{
				Kind:  SearchAnd,
				Left:  &SearchExpr{Kind: SearchText, Text: "holiday"},
				Right: &SearchExpr{Kind: SearchString, TagType: searchTypeFileType, ValueString: "Audio"},
			},
			want:  1,
			names: []string{"holiday song.mp3"},
		},
		{
			name: "OR of two terms",
			expr: &SearchExpr{
				Kind:  SearchOr,
				Left:  &SearchExpr{Kind: SearchText, Text: "song"},
				Right: &SearchExpr{Kind: SearchText, Text: "vacation"},
			},
			want:  2,
			names: []string{"holiday song.mp3", "vacation movie.avi"},
		},
		{
			name: "AND NOT",
			expr: &SearchExpr{
				Kind:  SearchAndNot,
				Left:  &SearchExpr{Kind: SearchText, Text: "movie"},
				Right: &SearchExpr{Kind: SearchText, Text: "vacation"},
			},
			want:  1,
			names: []string{"holiday movie.avi"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.FindBySearch(tc.expr)
			var names []string
			for _, f := range got {
				names = append(names, f.Name)
			}
			t.Logf("output: %d results %v", len(got), names)
			if len(got) != tc.want {
				t.Fatalf("got %d results %v, want %d %v", len(got), names, tc.want, tc.names)
			}
			// One row per file, not per source: the file with two sources must
			// still appear once.
			seen := map[string]bool{}
			for _, n := range names {
				if seen[n] {
					t.Fatalf("duplicate result for %q: GROUP BY did not collapse sources", n)
				}
				seen[n] = true
			}
			// Metadata must survive the ANY_VALUE() wrapping.
			for _, f := range got {
				if f.Name == "" {
					t.Fatal("result has an empty name; ANY_VALUE lost the column")
				}
			}
		})
	}
}

// TestMySQLFindBySearchEscapesWildcards pins L13 end to end: a % in a search term
// must match a literal %, the way the memory and Mongo engines already do — not act
// as a SQL wildcard. Against the pre-fix build `LIKE '%a%b%'` matches both "a%b"
// and "aXb"; with escaping only the literal "a%b" matches.
func TestMySQLFindBySearchEscapesWildcards(t *testing.T) {
	requireIntegration(t)
	engine, _ := startMySQL(t, "enode")

	client := ClientInfo{ID: 601, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID

	seed := []File{
		{Hash: []byte("dddddddddddddddd"), Name: "a%b", Size: 100, Type: "Doc"},
		{Hash: []byte("eeeeeeeeeeeeeeee"), Name: "aXb", Size: 200, Type: "Doc"},
	}
	for _, f := range seed {
		engine.AddFile(f, client)
		t.Logf("input: seeded %q", f.Name)
	}

	got := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "a%b"})
	var names []string
	for _, f := range got {
		names = append(names, f.Name)
	}
	t.Logf("output: search %q → %d result(s) %v", "a%b", len(got), names)
	if len(got) != 1 || names[0] != "a%b" {
		t.Fatalf("got %v, want exactly [\"a%%b\"] — %% must be a literal, not a wildcard", names)
	}
}

// Client tags are bound raw into varchar(8)/varchar(128)/varchar(255) and an
// ENUM. Under STRICT_TRANS_TABLES an over-length value or a non-member type
// aborts the whole sources INSERT, so the file is published but never becomes
// searchable — silently, because the error is only logged.
func TestMySQLAddFileWithHostileTags(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	client := ClientInfo{ID: 501, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef")}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID

	hostile := File{
		Hash: []byte("1111111111111111"),
		// Over varchar(255), and an extension over varchar(8).
		Name: strings.Repeat("x", 400) + ".torrent-part001",
		Size: 4096,
		// Not an ENUM member: eMule sends this for collection files.
		Type:      "EmuleCollection",
		Title:     strings.Repeat("t", 300),
		Artist:    strings.Repeat("a", 300),
		Album:     strings.Repeat("b", 300),
		Codec:     strings.Repeat("c", 100),
		Completed: 1,
	}
	t.Logf("input: name=%d runes ext=%q type=%q codec=%d runes",
		len([]rune(hostile.Name)), Ext(hostile.Name), hostile.Type, len([]rune(hostile.Codec)))

	engine.AddFile(hostile, client)

	var (
		name, ext, typ, codec string
		count                 int
	)
	if err := db.QueryRow(`SELECT COUNT(*) FROM sources`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: %d source rows", count)
	if count == 0 {
		t.Fatal("hostile tags aborted the sources INSERT: the file is published but unsearchable")
	}
	if err := db.QueryRow(`SELECT name, ext, type, codec FROM sources LIMIT 1`).Scan(&name, &ext, &typ, &codec); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: stored name=%d runes ext=%q type=%q codec=%d runes",
		len([]rune(name)), ext, typ, len([]rune(codec)))

	if len([]rune(name)) > maxNameLen {
		t.Fatalf("name exceeds varchar(%d): %d runes", maxNameLen, len([]rune(name)))
	}
	if len([]rune(ext)) > maxExtLen {
		t.Fatalf("ext exceeds varchar(%d): %q", maxExtLen, ext)
	}
	if _, ok := enumFileTypes[typ]; !ok {
		t.Fatalf("stored type %q is not an ENUM member", typ)
	}
	if len([]rune(codec)) > maxCodecLen {
		t.Fatalf("codec exceeds varchar(%d): %d runes", maxCodecLen, len([]rune(codec)))
	}

	// And the file must actually be findable, which is the point of the fix.
	found := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: strings.Repeat("x", 20)})
	t.Logf("output: search found %d results", len(found))
	if len(found) == 0 {
		t.Fatal("file with hostile tags was stored but is not searchable")
	}
}

// Sources were identified by (file, client_ed2k). The ed2k ID is per-session for
// LowIDs and follows the IP for HighIDs, so reconnecting produced a *second*
// source document; the first never matched Disconnect again and stayed online
// forever, inflating files.sources without bound.
func TestMongoSourceIdentitySurvivesEd2kIDChange(t *testing.T) {
	requireIntegration(t)

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mongo",
		Tag:        "7",
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mongo container: %v", err)
	}
	defer func() { _ = pool.Purge(resource) }()

	uri := fmt.Sprintf("mongodb://localhost:%s", resource.GetPort("27017/tcp"))
	engine, err := NewMongoDBEngine(MongoConfig{
		URI: uri, Database: "enode_source_identity", Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error { return engine.Init() }); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	defer engine.Close()

	userHash := []byte("0123456789abcdef")
	file := File{Hash: []byte("dddddddddddddddd"), Name: "shared.avi", Size: 4096, Type: "Video", Completed: 1}

	// Session 1: LowID 1000.
	first := ClientInfo{ID: 1000, IPv4: 0x0100007f, Port: 4662, Hash: userHash}
	if _, err := engine.Connect(first); err != nil {
		t.Fatal(err)
	}
	engine.AddFile(file, first)
	t.Logf("input: session 1 offered %q with ed2k ID=%d", file.Name, first.ID)
	engine.Disconnect(first)

	// Session 2: same user, different ed2k ID — a new LowID slot or a new IP.
	second := ClientInfo{ID: 2000, IPv4: 0x0200007f, Port: 4663, Hash: userHash}
	if _, err := engine.Connect(second); err != nil {
		t.Fatal(err)
	}
	engine.AddFile(file, second)
	t.Logf("input: session 2 offered the same file with ed2k ID=%d", second.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	total, err := engine.db.Collection("sources").CountDocuments(ctx, bson.M{"file_hash": file.Hash})
	if err != nil {
		t.Fatal(err)
	}
	online, err := engine.db.Collection("sources").CountDocuments(ctx,
		bson.M{"file_hash": file.Hash, "online": true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: %d source documents, %d online", total, online)

	if total != 1 {
		t.Fatalf("reconnecting with a new ed2k ID created %d source documents, want 1", total)
	}
	if online != 1 {
		t.Fatalf("expected exactly 1 online source, got %d", online)
	}

	// The current address must have been refreshed on the surviving document.
	var doc struct {
		ClientED2K uint32 `bson:"client_ed2k"`
	}
	if err := engine.db.Collection("sources").FindOne(ctx, bson.M{"file_hash": file.Hash}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: surviving document has client_ed2k=%d", doc.ClientED2K)
	if doc.ClientED2K != second.ID {
		t.Fatalf("client_ed2k not refreshed: got %d, want %d", doc.ClientED2K, second.ID)
	}

	// And it must resolve back to a usable source.
	sources := engine.GetSources(file.Hash, file.Size)
	t.Logf("output: GetSources returned %d sources", len(sources))
	if len(sources) != 1 {
		t.Fatalf("GetSources returned %d sources, want 1", len(sources))
	}
	if sources[0].ID != second.ID {
		t.Fatalf("source resolved to ed2k ID %d, want %d", sources[0].ID, second.ID)
	}

	// Disconnecting the live session must clear it, matching on hash.
	engine.Disconnect(second)
	stillOnline, err := engine.db.Collection("sources").CountDocuments(ctx,
		bson.M{"file_hash": file.Hash, "online": true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: after disconnect, %d sources still online", stillOnline)
	if stillOnline != 0 {
		t.Fatalf("%d sources remained online after disconnect", stillOnline)
	}
}
