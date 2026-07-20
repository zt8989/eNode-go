package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// startMongoEngine brings up mongo:7 and returns an initialized engine.
func startMongoEngine(t *testing.T, database string) *MongoDBEngine {
	t.Helper()

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
	t.Cleanup(func() { _ = pool.Purge(resource) })

	uri := fmt.Sprintf("mongodb://localhost:%s", resource.GetPort("27017/tcp"))
	engine, err := NewMongoDBEngine(MongoConfig{
		URI: uri, Database: database, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error { return engine.Init() }); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// The whole point of the sweep, on the engine where rows genuinely accumulate:
// an offline client older than the TTL goes, a live one stays regardless of age,
// and files.sources is recomputed rather than left overstating reality.
func TestMySQLCleanupStale(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	fileHash := []byte("fedcba9876543210")

	// Three clients offering one file; two will be aged out.
	var clients []ClientInfo
	for i := 0; i < 3; i++ {
		c := ClientInfo{
			ID:   uint32(500 + i),
			IPv4: 0x0100007f,
			Port: uint16(4662 + i),
			Hash: []byte{byte('a' + i), '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
		}
		storeID, err := engine.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = storeID
		engine.AddFile(File{Hash: fileHash, Size: 1024, Name: "movie.avi", Type: "Video"}, c)
		clients = append(clients, c)
	}

	// Two go offline and are backdated well past the TTL. The third stays online
	// and is backdated too — it must survive anyway.
	engine.Disconnect(clients[0])
	engine.Disconnect(clients[1])
	for _, c := range clients {
		if _, err := db.Exec(`UPDATE clients SET time_login = NOW() - INTERVAL 48 HOUR WHERE id = ?`, c.StoreID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE sources SET time_offer = NOW() - INTERVAL 48 HOUR WHERE id_client = ?`, c.StoreID); err != nil {
			t.Fatal(err)
		}
	}

	var before int
	if err := db.QueryRow(`SELECT sources FROM files WHERE hash = ?`, fileHash).Scan(&before); err != nil {
		t.Fatal(err)
	}
	t.Logf("input: 3 sources, 2 offline and 48h old, 1 online and 48h old; files.sources=%d", before)

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{KeepZeroSourceFiles: true})
	if err != nil {
		t.Fatal(err)
	}

	var remainingClients, remainingSources, filesSources, fileRows int
	_ = db.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&remainingClients)
	_ = db.QueryRow(`SELECT COUNT(*) FROM sources`).Scan(&remainingSources)
	_ = db.QueryRow(`SELECT COUNT(*) FROM files WHERE hash = ?`, fileHash).Scan(&fileRows)
	if err := db.QueryRow(`SELECT sources FROM files WHERE hash = ?`, fileHash).Scan(&filesSources); err != nil {
		t.Fatal(err)
	}
	t.Logf("output: removed clients=%d sources=%d; remaining clients=%d sources=%d files.sources=%d",
		result.Clients, result.Sources, remainingClients, remainingSources, filesSources)

	if result.Clients != 2 {
		t.Fatalf("removed %d clients, want 2", result.Clients)
	}
	if remainingClients != 1 {
		t.Fatalf("%d clients remain, want 1 — an online row was deleted", remainingClients)
	}
	// The FK cascade should have taken the two offline clients' sources with them.
	if remainingSources != 1 {
		t.Fatalf("%d source rows remain, want 1", remainingSources)
	}
	// This is the assertion that catches a sweep which deletes without recounting.
	if filesSources != remainingSources {
		t.Fatalf("files.sources=%d but %d source rows remain — the counter drifted",
			filesSources, remainingSources)
	}
	if fileRows != 1 {
		t.Fatalf("the file row was deleted despite keepZeroSourceFiles")
	}
}

// The composite indexes must exist and be *applicable* to the two predicates
// that matter. Deliberately not asserting that the optimizer picks them: on a
// small table a full scan is genuinely cheaper and MySQL will rightly choose
// one, so pinning the chosen plan would make this a flaky test of the optimizer
// rather than a test of the schema.
func TestMySQLCleanupIndexesExistAndApply(t *testing.T) {
	requireIntegration(t)
	engine, db := startMySQL(t, "enode")

	// A mix of online and offline rows, so the predicates are selective enough
	// for the optimizer to list the index in possible_keys.
	for i := 0; i < 40; i++ {
		c := ClientInfo{
			ID:   uint32(700 + i),
			IPv4: 0x0100007f,
			Port: uint16(4662 + i),
			Hash: []byte{byte('a' + i%26), byte('0' + i/26), '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
		}
		storeID, err := engine.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			c.StoreID = storeID
			engine.Disconnect(c)
		}
	}

	for _, tc := range []struct {
		table string
		index string
	}{
		{"clients", "online_time_login"},
		{"sources", "online_time_offer"},
	} {
		var count int
		err := db.QueryRow(
			`SELECT COUNT(*) FROM information_schema.statistics
			 WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`,
			tc.table, tc.index).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("output: index %s.%s columns indexed=%d", tc.table, tc.index, count)
		if count != 2 {
			t.Fatalf("index %s on %s has %d columns, want the 2-column composite",
				tc.index, tc.table, count)
		}
	}

	// And the optimizer must consider it for both shapes. possible_keys being
	// empty would mean the index cannot serve the predicate at all, which is a
	// schema bug rather than a costing decision.
	for _, query := range []string{
		`SELECT COUNT(*) FROM clients WHERE online = 1`,
		`SELECT id FROM clients WHERE online = 0 AND time_login < NOW() - INTERVAL 24 HOUR`,
	} {
		possible := explainPossibleKeys(t, db, query)
		t.Logf("output: %q -> possible_keys=%q", query, possible)
		if !strings.Contains(possible, "online_time_login") {
			t.Fatalf("online_time_login is not applicable to %q (possible_keys=%q)", query, possible)
		}
	}
}

// explainPossibleKeys returns the possible_keys column of the first EXPLAIN row,
// treating a SQL NULL as the empty string rather than the literal "<nil>".
func explainPossibleKeys(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	rows, err := db.Query("EXPLAIN " + query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		values := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, col := range cols {
			if col == "possible_keys" {
				return values[i].String
			}
		}
	}
	return ""
}

// Same contract on MongoDB, which has no foreign keys — the sweep has to remove
// a departed client's source documents itself.
func TestMongoCleanupStale(t *testing.T) {
	requireIntegration(t)
	engine := startMongoEngine(t, "enode_cleanup_test")

	fileHash := []byte("fedcba9876543210")
	var clients []ClientInfo
	for i := 0; i < 3; i++ {
		c := ClientInfo{
			ID:   uint32(600 + i),
			IPv4: 0x0100007f,
			Port: uint16(4662 + i),
			Hash: []byte{byte('a' + i), '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
		}
		storeID, err := engine.Connect(c)
		if err != nil {
			t.Fatal(err)
		}
		c.StoreID = storeID
		engine.AddFile(File{Hash: fileHash, Size: 1024, Name: "movie.avi", Type: "Video"}, c)
		clients = append(clients, c)
	}

	engine.Disconnect(clients[0])
	engine.Disconnect(clients[1])

	// Backdate everything so age is not what distinguishes them — only `online`.
	old := time.Now().Add(-48 * time.Hour)
	ctx, cancel := contextWithTimeout(engine)
	defer cancel()
	if _, err := engine.db.Collection("clients").UpdateMany(ctx, bsonAll(), bsonSetTime("time_login", old)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.db.Collection("sources").UpdateMany(ctx, bsonAll(), bsonSetTime("time_offer", old)); err != nil {
		t.Fatal(err)
	}

	t.Logf("input: 3 sources, 2 offline, all backdated 48h")

	result, err := engine.CleanupStale(24*time.Hour, CleanupOptions{KeepZeroSourceFiles: true})
	if err != nil {
		t.Fatal(err)
	}

	remainingClients, _ := engine.db.Collection("clients").CountDocuments(ctx, bsonAll())
	remainingSources, _ := engine.db.Collection("sources").CountDocuments(ctx, bsonAll())
	files := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "movie"})

	// Read the counter from the files collection, which is where it lives.
	// FindBySearch cannot be used for this: its pipeline runs over the sources
	// collection and decodes `sources` from the source document, which has no
	// such field, so it reports 0 unless the query happened to need the file
	// $lookup. (That is a separate divergence from MySQL, noted in the audit —
	// not something this sweep introduced or fixes.)
	var fileDoc struct {
		Sources uint32 `bson:"sources"`
	}
	if err := engine.db.Collection("files").FindOne(ctx, bson.M{"hash": fileHash}).Decode(&fileDoc); err != nil {
		t.Fatalf("read files counter: %v", err)
	}

	t.Logf("output: removed clients=%d sources=%d; remaining clients=%d sources=%d files.sources=%d",
		result.Clients, result.Sources, remainingClients, remainingSources, fileDoc.Sources)

	if result.Clients != 2 {
		t.Fatalf("removed %d clients, want 2", result.Clients)
	}
	if remainingClients != 1 {
		t.Fatalf("%d clients remain, want 1", remainingClients)
	}
	if remainingSources != 1 {
		t.Fatalf("%d source documents remain, want 1 — a departed client's sources were left behind", remainingSources)
	}
	if len(files) != 1 {
		t.Fatalf("search returned %d files, want 1", len(files))
	}
	// The assertion that catches a sweep which deletes without recounting.
	if int64(fileDoc.Sources) != remainingSources {
		t.Fatalf("files.sources=%d but %d source documents remain — the counter drifted",
			fileDoc.Sources, remainingSources)
	}
}

// Small helpers so the Mongo test can reach the driver without importing bson
// into every call site.
func contextWithTimeout(engine *MongoDBEngine) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), engine.cfg.Timeout)
}

func bsonAll() bson.M { return bson.M{} }

func bsonSetTime(field string, value time.Time) bson.M {
	return bson.M{"$set": bson.M{field: value}}
}
