package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
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
			KEY idx_id_ed2k (id_ed2k)
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
