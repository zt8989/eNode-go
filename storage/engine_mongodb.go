package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var (
	ErrMongoConfigInvalid  = errors.New("mongodb config is invalid")
	ErrMongoNotInitialized = errors.New("mongodb engine is not initialized")
)

type MongoConfig struct {
	URI      string
	Database string
	Timeout  time.Duration
}

type MongoDBEngine struct {
	cfg     MongoConfig
	client  *mongo.Client
	db      *mongo.Database
	servers []Server
}

func NewMongoDBEngine(cfg MongoConfig) (*MongoDBEngine, error) {
	if cfg.URI == "" || cfg.Database == "" {
		return nil, ErrMongoConfigInvalid
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &MongoDBEngine{cfg: cfg}, nil
}

func (m *MongoDBEngine) ensureDB() error {
	if m.db == nil {
		return ErrMongoNotInitialized
	}
	return nil
}

func (m *MongoDBEngine) Init() error {
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(m.cfg.URI))
	if err != nil {
		return err
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return err
	}
	db := client.Database(m.cfg.Database)
	m.client = client
	m.db = db

	_, _ = db.Collection("clients").UpdateMany(ctx, bson.M{}, bson.M{"$set": bson.M{"online": false}})
	_, _ = db.Collection("sources").UpdateMany(ctx, bson.M{}, bson.M{"$set": bson.M{"online": false}})

	_, _ = db.Collection("clients").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "hash", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	_, _ = db.Collection("files").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "hash", Value: 1}, {Key: "size", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	_, _ = db.Collection("sources").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "file_hash", Value: 1}, {Key: "file_size", Value: 1}, {Key: "client_ed2k", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return nil
}

func (m *MongoDBEngine) Close() error {
	if m.client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	return m.client.Disconnect(ctx)
}

func (m *MongoDBEngine) ClientsCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	n, err := m.db.Collection("clients").CountDocuments(ctx, bson.M{"online": true})
	if err != nil {
		return 0
	}
	return int(n)
}

func (m *MongoDBEngine) IsConnected(info ClientInfo) bool {
	if err := m.ensureDB(); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	n, err := m.db.Collection("clients").CountDocuments(ctx, bson.M{"hash": info.Hash, "online": true})
	return err == nil && n > 0
}

func (m *MongoDBEngine) Connect(info ClientInfo) (int, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	doc := bson.M{
		"hash":       info.Hash,
		"id_ed2k":    info.ID,
		"ipv4":       info.IPv4,
		"port":       info.Port,
		"online":     true,
		"time_login": time.Now(),
	}
	_, err := m.db.Collection("clients").UpdateOne(
		ctx,
		bson.M{"hash": info.Hash},
		bson.M{"$set": doc},
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil {
		return 0, err
	}
	var got struct {
		IDEd2K uint32 `bson:"id_ed2k"`
	}
	if err := m.db.Collection("clients").FindOne(ctx, bson.M{"hash": info.Hash}).Decode(&got); err != nil {
		return 0, err
	}
	return int(got.IDEd2K), nil
}

func (m *MongoDBEngine) Disconnect(info ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	_, _ = m.db.Collection("clients").UpdateOne(ctx, bson.M{"id_ed2k": info.ID}, bson.M{"$set": bson.M{"online": false}})
	_, _ = m.db.Collection("sources").UpdateMany(ctx, bson.M{"client_ed2k": info.ID}, bson.M{"$set": bson.M{"online": false}})
}

func (m *MongoDBEngine) FilesCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	n, err := m.db.Collection("files").CountDocuments(ctx, bson.M{})
	if err != nil {
		return 0
	}
	return int(n)
}

func (m *MongoDBEngine) AddFile(file File, clientInfo ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	_, _ = m.db.Collection("files").UpdateOne(
		ctx,
		bson.M{"hash": file.Hash, "size": file.Size},
		bson.M{"$set": bson.M{"hash": file.Hash, "size": file.Size, "time_offer": time.Now()}},
		options.UpdateOne().SetUpsert(true),
	)

	typ := file.Type
	if typ == "" {
		typ = GetFileType(file.Name)
	}
	src := bson.M{
		"file_hash":   file.Hash,
		"file_size":   file.Size,
		"client_ed2k": clientInfo.ID,
		"name":        file.Name,
		"ext":         Ext(file.Name),
		"type":        typ,
		"title":       file.Title,
		"artist":      file.Artist,
		"album":       file.Album,
		"length":      file.Runtime,
		"bitrate":     file.Bitrate,
		"codec":       file.Codec,
		"online":      true,
		"complete":    file.Completed > 0,
		"time_offer":  time.Now(),
	}
	_, _ = m.db.Collection("sources").UpdateOne(
		ctx,
		bson.M{"file_hash": file.Hash, "file_size": file.Size, "client_ed2k": clientInfo.ID},
		bson.M{"$set": src},
		options.UpdateOne().SetUpsert(true),
	)

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"file_hash": file.Hash, "file_size": file.Size}}},
		{{Key: "$group", Value: bson.M{
			"_id":       bson.M{"file_hash": "$file_hash", "file_size": "$file_size"},
			"sources":   bson.M{"$sum": 1},
			"completed": bson.M{"$sum": bson.M{"$cond": []any{"$complete", 1, 0}}},
		}}},
	}
	cur, err := m.db.Collection("sources").Aggregate(ctx, pipeline)
	if err != nil {
		return
	}
	defer cur.Close(ctx)
	var agg []struct {
		Sources   int32 `bson:"sources"`
		Completed int32 `bson:"completed"`
	}
	if err := cur.All(ctx, &agg); err != nil || len(agg) == 0 {
		return
	}
	_, _ = m.db.Collection("files").UpdateOne(
		ctx,
		bson.M{"hash": file.Hash, "size": file.Size},
		bson.M{"$set": bson.M{
			"sources":     agg[0].Sources,
			"completed":   agg[0].Completed,
			"source_id":   clientInfo.ID,
			"source_port": clientInfo.Port,
		}},
	)
}

func (m *MongoDBEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	return m.getSourcesByFile(ctx, fileHash, fileSize)
}

func (m *MongoDBEngine) GetSourcesByHash(fileHash []byte) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	cur, err := m.db.Collection("sources").Find(
		ctx,
		bson.M{"file_hash": fileHash},
		options.Find().SetSort(bson.D{{Key: "online", Value: -1}, {Key: "time_offer", Value: -1}}).SetLimit(255),
	)
	if err != nil {
		return nil
	}
	defer cur.Close(ctx)
	var srcDocs []struct {
		ClientED2K uint32 `bson:"client_ed2k"`
	}
	if err := cur.All(ctx, &srcDocs); err != nil {
		return nil
	}
	out := make([]Source, 0, len(srcDocs))
	for _, s := range srcDocs {
		var cdoc struct {
			IDEd2K uint32 `bson:"id_ed2k"`
			Port   uint16 `bson:"port"`
		}
		if err := m.db.Collection("clients").FindOne(ctx, bson.M{"id_ed2k": s.ClientED2K}).Decode(&cdoc); err == nil {
			out = append(out, Source{ID: cdoc.IDEd2K, Port: cdoc.Port})
		}
	}
	return out
}

func (m *MongoDBEngine) getSourcesByFile(ctx context.Context, fileHash []byte, fileSize uint64) []Source {
	cur, err := m.db.Collection("sources").Find(
		ctx,
		bson.M{"file_hash": fileHash, "file_size": fileSize},
		options.Find().SetSort(bson.D{{Key: "online", Value: -1}, {Key: "time_offer", Value: -1}}).SetLimit(255),
	)
	if err != nil {
		return nil
	}
	defer cur.Close(ctx)
	var srcDocs []struct {
		ClientED2K uint32 `bson:"client_ed2k"`
	}
	if err := cur.All(ctx, &srcDocs); err != nil {
		return nil
	}
	out := make([]Source, 0, len(srcDocs))
	for _, s := range srcDocs {
		var cdoc struct {
			IDEd2K uint32 `bson:"id_ed2k"`
			Port   uint16 `bson:"port"`
		}
		if err := m.db.Collection("clients").FindOne(ctx, bson.M{"id_ed2k": s.ClientED2K}).Decode(&cdoc); err == nil {
			out = append(out, Source{ID: cdoc.IDEd2K, Port: cdoc.Port})
		}
	}
	return out
}

func (m *MongoDBEngine) FindByNameContains(term string) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()
	cur, err := m.db.Collection("sources").Find(
		ctx,
		bson.M{"name": bson.M{"$regex": fmt.Sprintf(".*%s.*", term)}},
		options.Find().SetLimit(255),
	)
	if err != nil {
		return nil
	}
	defer cur.Close(ctx)
	var src []struct {
		FileHash []byte `bson:"file_hash"`
		FileSize uint64 `bson:"file_size"`
		Name     string `bson:"name"`
		Type     string `bson:"type"`
		Title    string `bson:"title"`
		Artist   string `bson:"artist"`
		Album    string `bson:"album"`
		Runtime  uint32 `bson:"length"`
		Bitrate  uint32 `bson:"bitrate"`
		Codec    string `bson:"codec"`
	}
	if err := cur.All(ctx, &src); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []File
	for _, s := range src {
		key := string(s.FileHash) + ":" + fmt.Sprintf("%d", s.FileSize)
		if seen[key] {
			continue
		}
		seen[key] = true
		var fdoc struct {
			Hash       []byte `bson:"hash"`
			Size       uint64 `bson:"size"`
			Sources    uint32 `bson:"sources"`
			Completed  uint32 `bson:"completed"`
			SourceID   uint32 `bson:"source_id"`
			SourcePort uint16 `bson:"source_port"`
		}
		if err := m.db.Collection("files").FindOne(ctx, bson.M{"hash": s.FileHash, "size": s.FileSize}).Decode(&fdoc); err != nil {
			continue
		}
		out = append(out, File{
			Hash: fdoc.Hash, Name: s.Name, Size: fdoc.Size, Type: s.Type,
			Sources: fdoc.Sources, Completed: fdoc.Completed, Title: s.Title, Artist: s.Artist,
			Album: s.Album, Runtime: s.Runtime, Bitrate: s.Bitrate, Codec: s.Codec,
			SourceID: fdoc.SourceID, SourcePort: fdoc.SourcePort,
		})
	}
	return out
}

func (m *MongoDBEngine) ServersCount() int {
	return len(m.servers)
}

func (m *MongoDBEngine) AddServer(server Server) {
	m.servers = append(m.servers, server)
}

func (m *MongoDBEngine) ServersAll() []Server {
	return append([]Server(nil), m.servers...)
}
