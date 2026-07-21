package ed2k

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"enode/storage"
	"enode/tests"

	_ "github.com/go-sql-driver/mysql"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func requireED2KIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("ENODE_INTEGRATION") != "1" {
		t.Skip("set ENODE_INTEGRATION=1 to run integration tests")
	}
}

func TestTCPLoginAndOfferFilesPersistToMySQL(t *testing.T) {
	requireED2KIntegration(t)

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
		return db.Ping()
	}); err != nil {
		t.Fatalf("mysql not ready: %v", err)
	}
	defer db.Close()

	// Init creates the schema from the resolved relative path on first connect
	// (this test runs from ed2k/, so FixRelativeTestingPath walks up to the module
	// root); the raw db handle above is kept for the direct row assertions below.
	engine, err := storage.NewMySQLEngine(storage.MySQLConfig{
		Host: "localhost", Port: mustAtoiForED2KIntegration(port), User: "root", Pass: "root", Database: "enode",
		MaxOpenConns: 4, MaxIdleConns: 2,
		SchemaFile: tests.FixRelativeTestingPath("misc/enode.sql"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Init(); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	clientHash := []byte("0123456789abcdef")
	fileHash := []byte("fedcba9876543210")

	client := simulateLoginAndOfferFiles(t, engine, clientHash, fileHash, "movie.mkv", 1024)

	var nClients int
	if err := db.QueryRow(`SELECT COUNT(*) FROM clients WHERE hash = ? AND online = 1`, clientHash).Scan(&nClients); err != nil {
		t.Fatal(err)
	}
	if nClients == 0 {
		t.Fatalf("expected clients row for hash=%x", clientHash)
	}

	var nFiles int
	if err := db.QueryRow(`SELECT COUNT(*) FROM files WHERE hash = ? AND size = ?`, fileHash, 1024).Scan(&nFiles); err != nil {
		t.Fatal(err)
	}
	if nFiles == 0 {
		t.Fatalf("expected files row for hash=%x size=1024", fileHash)
	}

	var nSources int
	if err := db.QueryRow(
		`SELECT COUNT(*)
		 FROM sources s
		 INNER JOIN files f ON f.id = s.id_file
		 WHERE f.hash = ? AND f.size = ? AND s.id_client = ?`,
		fileHash, 1024, client.info.StoreID,
	).Scan(&nSources); err != nil {
		t.Fatal(err)
	}
	if nSources == 0 {
		t.Fatalf("expected sources row for hash=%x size=1024 storeID=%d", fileHash, client.info.StoreID)
	}
}

func TestTCPLoginAndOfferFilesPersistToMongo(t *testing.T) {
	requireED2KIntegration(t)

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
	engine, err := storage.NewMongoDBEngine(storage.MongoConfig{
		URI: uri, Database: "enode_tcp_ops_test", Timeout: 10 * time.Second,
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

	clientHash := []byte("0123456789abcdef")
	fileHash := []byte("fedcba9876543210")

	client := simulateLoginAndOfferFiles(t, engine, clientHash, fileHash, "track.mp3", 2048)

	mongoClient, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer mongoClient.Disconnect(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db := mongoClient.Database("enode_tcp_ops_test")

	nClients, err := db.Collection("clients").CountDocuments(ctx, bson.M{"hash": clientHash, "online": true})
	if err != nil {
		t.Fatal(err)
	}
	if nClients == 0 {
		t.Fatalf("expected clients document for hash=%x", clientHash)
	}

	nFiles, err := db.Collection("files").CountDocuments(ctx, bson.M{"hash": fileHash, "size": uint64(2048)})
	if err != nil {
		t.Fatal(err)
	}
	if nFiles == 0 {
		t.Fatalf("expected files document for hash=%x size=2048", fileHash)
	}

	nSources, err := db.Collection("sources").CountDocuments(ctx, bson.M{
		"file_hash":   fileHash,
		"file_size":   uint64(2048),
		"client_ed2k": client.info.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if nSources == 0 {
		t.Fatalf("expected sources document for hash=%x size=2048 client_ed2k=%d", fileHash, client.info.ID)
	}
}

func simulateLoginAndOfferFiles(
	t *testing.T,
	engine storage.Engine,
	clientHash []byte,
	fileHash []byte,
	fileName string,
	fileSize uint64,
) *tcpClient {
	t.Helper()

	rt := NewServerRuntime(TCPRuntimeConfig{
		Address:           "127.0.0.1",
		Port:              4661,
		Hash:              []byte("1111111111111111"),
		AllowLowIDs:       true,
		ConnectionTimeout: 50 * time.Millisecond,
	}, UDPRuntimeConfig{}, engine)

	client := newTCPClient(rt, &mockConn{}, false)

	dispatchIncomingTCPPacket(t, client, []PacketItem{
		{Type: TypeUint8, Value: OpLoginRequest},
		{Type: TypeHash, Value: clientHash},
		{Type: TypeUint32, Value: uint32(0)},
		{Type: TypeUint16, Value: uint16(0)},
		{Type: TypeTags, Value: []Tag{}},
	})

	if !client.logged {
		t.Fatalf("expected logged client after OP_LOGINREQUEST")
	}
	if client.info.StoreID == 0 {
		t.Fatalf("expected non-zero storeID after OP_LOGINREQUEST")
	}

	offer := []PacketItem{
		{Type: TypeUint8, Value: OpOfferFiles},
		{Type: TypeUint32, Value: uint32(1)},
	}
	AddFile(&offer, SharedFile{
		Name:       fileName,
		Size:       fileSize,
		Hash:       fileHash,
		SourceID:   ValCompleteID,
		SourcePort: ValCompletePort,
		Completed:  1,
		Sources:    1,
	})
	dispatchIncomingTCPPacket(t, client, offer)

	return client
}

func dispatchIncomingTCPPacket(t *testing.T, client *tcpClient, items []PacketItem) {
	t.Helper()

	wire, err := MakePacket(PrED2K, items)
	if err != nil {
		t.Fatal(err)
	}

	packet := NewPacket()
	if err := packet.Init(NewBufferFromBytes(wire.Bytes())); err != nil {
		t.Fatal(err)
	}
	if packet.Status != PsReady {
		t.Fatalf("unexpected packet status=%d", packet.Status)
	}

	client.handlePacket(packet)
}

func mustAtoiForED2KIntegration(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
