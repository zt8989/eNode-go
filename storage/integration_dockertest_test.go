package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("ENODE_INTEGRATION") != "1" {
		t.Skip("set ENODE_INTEGRATION=1 to run integration tests")
	}
}

func TestMySQLEngineWithDockertest(t *testing.T) {
	requireIntegration(t)

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "8.0",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=root",
			"MYSQL_DATABASE=enode",
		},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("start mysql container: %v", err)
	}
	defer func() { _ = pool.Purge(resource) }()

	port := resource.GetPort("3306/tcp")
	dsn := fmt.Sprintf("root:root@tcp(localhost:%s)/enode?parseTime=true", port)

	var db *sql.DB
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		var e error
		db, e = sql.Open("mysql", dsn)
		if e != nil {
			return e
		}
		if e = db.Ping(); e != nil {
			return e
		}
		return applyMySQLSchema(db)
	}); err != nil {
		t.Fatalf("mysql not ready: %v", err)
	}
	defer db.Close()

	engine, err := NewMySQLEngine(MySQLConfig{
		Host: "localhost", Port: mustAtoi(port), User: "root", Pass: "root", Database: "enode",
		MaxOpenConns: 4, MaxIdleConns: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	client := ClientInfo{
		ID: 101, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef"),
	}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID
	if !engine.IsConnected(client) {
		t.Fatalf("expected connected client")
	}

	file := File{
		Hash: []byte("fedcba9876543210"), Name: "movie.mkv", Size: 1024,
		Completed: 1, SourceID: client.ID, SourcePort: client.Port,
	}
	engine.AddFile(file, client)
	if engine.FilesCount() < 1 {
		t.Fatalf("expected files count > 0")
	}
	sources := engine.GetSources(file.Hash, file.Size)
	if len(sources) == 0 {
		t.Fatalf("expected sources for file")
	}
	found := engine.FindByNameContains("movie")
	if len(found) == 0 {
		t.Fatalf("expected find results")
	}

	engine.Disconnect(client)
	if engine.IsConnected(client) {
		t.Fatalf("expected disconnected client")
	}
}

func TestMongoEngineWithDockertest(t *testing.T) {
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
		URI: uri, Database: "enode_test", Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error {
		return engine.Init()
	}); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	defer engine.Close()

	client := ClientInfo{
		ID: 202, IPv4: 0x0100007f, Port: 4662, Hash: []byte("0123456789abcdef"),
	}
	storeID, err := engine.Connect(client)
	if err != nil {
		t.Fatal(err)
	}
	client.StoreID = storeID
	if !engine.IsConnected(client) {
		t.Fatalf("expected connected client")
	}

	file := File{
		Hash: []byte("fedcba9876543210"), Name: "track.mp3", Size: 2048,
		Completed: 1, SourceID: client.ID, SourcePort: client.Port,
	}
	engine.AddFile(file, client)
	if engine.FilesCount() < 1 {
		t.Fatalf("expected files count > 0")
	}
	sources := engine.GetSources(file.Hash, file.Size)
	if len(sources) == 0 {
		t.Fatalf("expected sources for file")
	}
	found := engine.FindByNameContains("track")
	if len(found) == 0 {
		t.Fatalf("expected find results")
	}

	engine.Disconnect(client)
	if engine.IsConnected(client) {
		t.Fatalf("expected disconnected client")
	}

	// sanity-check collections exist and have documents
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(context.Background())
	n, err := c.Database("enode_test").Collection("files").CountDocuments(ctx, bson.M{})
	if err != nil || n == 0 {
		t.Fatalf("expected mongodb files documents, got n=%d err=%v", n, err)
	}
}

// TestMongoFindBySearch exercises FindBySearch against a real MongoDB. Every case
// below returned zero results (or errored, silently) before the search pipeline
// was fixed: $text was emitted outside the first stage, $meta was referenced with
// no $text stage, and OR/AND-NOT were treated as a fatal condition.
func TestMongoFindBySearch(t *testing.T) {
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
		URI: uri, Database: "enode_search_test", Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool.MaxWait = 2 * time.Minute
	if err := pool.Retry(func() error { return engine.Init() }); err != nil {
		t.Fatalf("mongo not ready: %v", err)
	}
	defer engine.Close()

	client := ClientInfo{ID: 303, IPv4: 0x0100007f, Port: 4662, Hash: []byte("fedcba9876543210")}
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
		t.Logf("input: seeded %q type=%s size=%d", f.Name, f.Type, f.Size)
	}

	movieText := &SearchExpr{Kind: SearchText, Text: "movie"}
	videoType := &SearchExpr{Kind: SearchString, TagType: searchTypeFileType, ValueString: "Video"}

	cases := []struct {
		name      string
		expr      *SearchExpr
		wantNames []string
	}{
		{
			// Hoisted $text at stage 0. Previously the same filter was emitted
			// twice, putting a $text in stage 2, which MongoDB rejects.
			name:      "bare text",
			expr:      movieText,
			wantNames: []string{"holiday movie.avi", "vacation movie.avi"},
		},
		{
			// Hoisted $text plus a later $match.
			name:      "text AND type",
			expr:      &SearchExpr{Kind: SearchAnd, Left: movieText, Right: videoType},
			wantNames: []string{"holiday movie.avi", "vacation movie.avi"},
		},
		{
			// Regex fallback: $text is illegal inside $or.
			name: "OR of two text terms",
			expr: &SearchExpr{Kind: SearchOr,
				Left:  &SearchExpr{Kind: SearchText, Text: "song"},
				Right: &SearchExpr{Kind: SearchText, Text: "vacation"}},
			wantNames: []string{"holiday song.mp3", "vacation movie.avi"},
		},
		{
			// Regex fallback: the eMule "-word" exclusion.
			name: "AND NOT",
			expr: &SearchExpr{Kind: SearchAndNot,
				Left:  &SearchExpr{Kind: SearchText, Text: "holiday"},
				Right: &SearchExpr{Kind: SearchText, Text: "song"}},
			wantNames: []string{"holiday movie.avi"},
		},
		{
			// Regex fallback: two text leaves cannot both be hoisted.
			name: "two text leaves",
			expr: &SearchExpr{Kind: SearchAnd,
				Left:  &SearchExpr{Kind: SearchText, Text: "holiday"},
				Right: &SearchExpr{Kind: SearchText, Text: "movie"}},
			wantNames: []string{"holiday movie.avi"},
		},
		{
			// No $text stage at all: previously the unconditional $meta made this
			// fail with "query requires text score metadata".
			name:      "non-text only",
			expr:      videoType,
			wantNames: []string{"holiday movie.avi", "vacation movie.avi"},
		},
		{
			// Exercises the $lookup path (file.sources lives on the files doc).
			name: "sources threshold via lookup",
			expr: &SearchExpr{Kind: SearchUInt32, TagType: searchTypeSources, ValueUint: 0},
			wantNames: []string{
				"holiday movie.avi", "holiday song.mp3", "vacation movie.avi",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.FindBySearch(tc.expr)
			names := make([]string, 0, len(got))
			for _, f := range got {
				names = append(names, f.Name)
			}
			sort.Strings(names)
			want := append([]string(nil), tc.wantNames...)
			sort.Strings(want)

			t.Logf("output: %d result(s): %v", len(got), names)

			if len(names) != len(want) {
				t.Fatalf("result count mismatch: got %v, want %v", names, want)
			}
			for i := range want {
				if names[i] != want[i] {
					t.Fatalf("result mismatch: got %v, want %v", names, want)
				}
			}
		})
	}
}

// applyMySQLSchema builds the test schema.
//
// NOTE: this is a hand-maintained duplicate of misc/enode.sql, not a loader for
// it, so a column or index added to the real schema is invisible here until it
// is added below as well. That is how the (online, time_login) index came to be
// missing from every integration run despite being present in misc/enode.sql.
// Keep the two in step, or replace this with a parser for the real file.
func applyMySQLSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			hash BINARY(16) NOT NULL,
			id_ed2k INT UNSIGNED NOT NULL DEFAULT 0,
			ipv4 INT UNSIGNED NOT NULL DEFAULT 0,
			port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
			time_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			online TINYINT(1) NOT NULL DEFAULT 0,
			PRIMARY KEY (id),
			UNIQUE KEY uniq_hash (hash),
			KEY idx_id_ed2k (id_ed2k),
			KEY online_time_login (online,time_login)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,
		`CREATE TABLE IF NOT EXISTS files (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			hash BINARY(16) NOT NULL,
			size BIGINT NOT NULL DEFAULT 0,
			time_creation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			time_offer TIMESTAMP NULL DEFAULT NULL,
			source_id INT UNSIGNED NOT NULL DEFAULT 0,
			source_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
			sources INT NOT NULL DEFAULT 0,
			completed INT NOT NULL DEFAULT 0,
			PRIMARY KEY (id),
			UNIQUE KEY uniq_hash_size (hash,size),
			KEY idx_hash (hash),
			KEY idx_size (size)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,
		`CREATE TABLE IF NOT EXISTS sources (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			id_file BIGINT UNSIGNED NOT NULL,
			id_client BIGINT UNSIGNED NOT NULL,
			name VARCHAR(255) NOT NULL DEFAULT '',
			ext VARCHAR(8) NOT NULL DEFAULT '',
			time_offer TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			type ENUM('Image','Audio','Video','Pro','Doc','') NOT NULL DEFAULT '',
			rating TINYINT UNSIGNED NOT NULL DEFAULT 0,
			title VARCHAR(128) NOT NULL DEFAULT '',
			artist VARCHAR(128) NOT NULL DEFAULT '',
			album VARCHAR(128) NOT NULL DEFAULT '',
			length INT UNSIGNED NOT NULL DEFAULT 0,
			bitrate INT UNSIGNED NOT NULL DEFAULT 0,
			codec VARCHAR(32) NOT NULL DEFAULT '',
			online TINYINT(1) NOT NULL DEFAULT 0,
			complete TINYINT(1) NOT NULL DEFAULT 0,
			PRIMARY KEY (id),
			UNIQUE KEY uniq_file_client (id_file,id_client),
			KEY idx_file (id_file),
			KEY idx_client (id_client),
			KEY online_time_offer (online,time_offer),
			CONSTRAINT fk_sources_file FOREIGN KEY (id_file) REFERENCES files(id) ON DELETE CASCADE ON UPDATE CASCADE,
			CONSTRAINT fk_sources_client FOREIGN KEY (id_client) REFERENCES clients(id) ON DELETE CASCADE ON UPDATE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func mustAtoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
