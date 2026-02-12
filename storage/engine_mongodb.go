package storage

import (
	"context"
	"errors"
	"strconv"
	"strings"
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
	_, _ = db.Collection("sources").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "file_hash", Value: 1}, {Key: "file_size", Value: 1}}},
		{Keys: bson.D{{Key: "name", Value: "text"}}},
		{Keys: bson.D{{Key: "type", Value: 1}}},
		{Keys: bson.D{{Key: "ext", Value: 1}}},
		{Keys: bson.D{{Key: "codec", Value: 1}}},
		{Keys: bson.D{{Key: "bitrate", Value: 1}}},
		{Keys: bson.D{{Key: "length", Value: 1}}},
		{Keys: bson.D{{Key: "file_size", Value: 1}}},
	})
	_, _ = db.Collection("files").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "sources", Value: 1}}},
		{Keys: bson.D{{Key: "completed", Value: 1}}},
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
			Hash   []byte `bson:"hash"`
		}
		if err := m.db.Collection("clients").FindOne(ctx, bson.M{"id_ed2k": s.ClientED2K}).Decode(&cdoc); err == nil {
			out = append(out, Source{ID: cdoc.IDEd2K, Port: cdoc.Port, UserHash: append([]byte(nil), cdoc.Hash...)})
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
			Hash   []byte `bson:"hash"`
		}
		if err := m.db.Collection("clients").FindOne(ctx, bson.M{"id_ed2k": s.ClientED2K}).Decode(&cdoc); err == nil {
			out = append(out, Source{ID: cdoc.IDEd2K, Port: cdoc.Port, UserHash: append([]byte(nil), cdoc.Hash...)})
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
		bson.M{"$text": bson.M{"$search": term}},
		options.Find().
			SetLimit(255).
			SetProjection(bson.M{"score": bson.M{"$meta": "textScore"}}).
			SetSort(bson.D{{Key: "score", Value: bson.M{"$meta": "textScore"}}}),
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
		key := string(s.FileHash) + ":" + strconv.FormatUint(s.FileSize, 10)
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

func (m *MongoDBEngine) FindBySearch(expr *SearchExpr) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	if expr == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	sourceMatch, ok := mongoSourceConjunctFilter(expr)
	fullMatch, needsFile, usesText := mongoFilter(expr)
	if !ok || fullMatch == nil {
		return nil
	}

	pipeline := mongo.Pipeline{}
	if sourceMatch != nil {
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: sourceMatch}})
	}
	if needsFile {
		pipeline = append(pipeline,
			bson.D{{
				Key: "$lookup", Value: bson.M{
					"from": "files",
					"let":  bson.M{"h": "$file_hash", "s": "$file_size"},
					"pipeline": mongo.Pipeline{
						bson.D{{Key: "$match", Value: bson.M{
							"$expr": bson.M{
								"$and": []bson.M{
									{"$eq": []any{"$hash", "$$h"}},
									{"$eq": []any{"$size", "$$s"}},
								},
							},
						}}},
					},
					"as": "file",
				},
			}},
			bson.D{{Key: "$unwind", Value: "$file"}},
		)
	}
	pipeline = append(pipeline,
		bson.D{{Key: "$match", Value: fullMatch}},
		bson.D{{Key: "$addFields", Value: bson.M{"_textScore": bson.M{"$meta": "textScore"}}}},
		bson.D{{Key: "$group", Value: bson.M{
			"_id":         bson.M{"hash": "$file_hash", "size": "$file_size"},
			"hash":        bson.M{"$first": "$file_hash"},
			"size":        bson.M{"$first": "$file_size"},
			"name":        bson.M{"$first": "$name"},
			"type":        bson.M{"$first": "$type"},
			"title":       bson.M{"$first": "$title"},
			"artist":      bson.M{"$first": "$artist"},
			"album":       bson.M{"$first": "$album"},
			"runtime":     bson.M{"$first": "$length"},
			"bitrate":     bson.M{"$first": "$bitrate"},
			"codec":       bson.M{"$first": "$codec"},
			"sources":     bson.M{"$first": "$file.sources"},
			"completed":   bson.M{"$first": "$file.completed"},
			"source_id":   bson.M{"$first": "$file.source_id"},
			"source_port": bson.M{"$first": "$file.source_port"},
			"score":       bson.M{"$first": "$_textScore"},
		}}},
	)
	if usesText {
		pipeline = append(pipeline, bson.D{{Key: "$sort", Value: bson.M{"score": -1}}})
	}
	pipeline = append(pipeline,
		bson.D{{Key: "$limit", Value: 255}},
	)

	cur, err := m.db.Collection("sources").Aggregate(ctx, pipeline, options.Aggregate().SetAllowDiskUse(true))
	if err != nil {
		return nil
	}
	defer cur.Close(ctx)

	var out []File
	for cur.Next(ctx) {
		var doc struct {
			Hash       []byte  `bson:"hash"`
			Size       uint64  `bson:"size"`
			Name       string  `bson:"name"`
			Type       string  `bson:"type"`
			Title      string  `bson:"title"`
			Artist     string  `bson:"artist"`
			Album      string  `bson:"album"`
			Runtime    uint32  `bson:"runtime"`
			Bitrate    uint32  `bson:"bitrate"`
			Codec      string  `bson:"codec"`
			Sources    uint32  `bson:"sources"`
			Completed  uint32  `bson:"completed"`
			SourceID   uint32  `bson:"source_id"`
			SourcePort uint16  `bson:"source_port"`
			Score      float64 `bson:"score"`
		}
		if err := cur.Decode(&doc); err != nil {
			continue
		}
		out = append(out, File{
			Hash: doc.Hash, Name: doc.Name, Size: doc.Size, Type: doc.Type,
			Sources: doc.Sources, Completed: doc.Completed, Title: doc.Title, Artist: doc.Artist,
			Album: doc.Album, Runtime: doc.Runtime, Bitrate: doc.Bitrate, Codec: doc.Codec,
			SourceID: doc.SourceID, SourcePort: doc.SourcePort,
		})
	}
	return out
}

func mongoSourceConjunctFilter(expr *SearchExpr) (bson.M, bool) {
	if expr == nil {
		return nil, true
	}
	switch expr.Kind {
	case SearchAnd:
		l, ok := mongoSourceConjunctFilter(expr.Left)
		if !ok {
			return nil, false
		}
		r, ok := mongoSourceConjunctFilter(expr.Right)
		if !ok {
			return nil, false
		}
		if l == nil {
			return r, true
		}
		if r == nil {
			return l, true
		}
		return bson.M{"$and": []bson.M{l, r}}, true
	case SearchOr, SearchAndNot:
		return nil, false
	default:
		f, needsFile, _ := mongoFilter(expr)
		if f == nil || needsFile {
			return nil, true
		}
		return f, true
	}
}

func mongoFilter(expr *SearchExpr) (bson.M, bool, bool) {
	if expr == nil {
		return nil, false, false
	}
	switch expr.Kind {
	case SearchText:
		terms := splitTerms(expr.Text)
		if len(terms) == 0 {
			return nil, false, false
		}
		return bson.M{"$text": bson.M{"$search": strings.Join(terms, " ")}}, false, true
	case SearchString:
		if expr.TagType == searchTypeText {
			return mongoFilter(&SearchExpr{Kind: SearchText, Text: expr.ValueString})
		}
		switch expr.TagType {
		case searchTypeFileType:
			return bson.M{"type": expr.ValueString}, false, false
		case searchTypeExt:
			return bson.M{"ext": expr.ValueString}, false, false
		case searchTypeCodec:
			return bson.M{"codec": expr.ValueString}, false, false
		default:
			return nil, false, false
		}
	case SearchUInt32, SearchUInt64:
		val := expr.ValueUint
		switch expr.TagType {
		case searchTypeSizeGt:
			return bson.M{"file_size": bson.M{"$gt": val}}, false, false
		case searchTypeSizeLt:
			return bson.M{"file_size": bson.M{"$lt": val}}, false, false
		case searchTypeSources:
			return bson.M{"file.sources": bson.M{"$gt": val}}, true, false
		case searchTypeBitrate:
			return bson.M{"bitrate": bson.M{"$gt": val}}, false, false
		case searchTypeDuration:
			return bson.M{"length": bson.M{"$gt": val}}, false, false
		case searchTypeComplete:
			return bson.M{"file.completed": bson.M{"$gt": val}}, true, false
		default:
			return nil, false, false
		}
	case SearchAnd, SearchOr, SearchAndNot:
		l, lNeedsFile, lUsesText := mongoFilter(expr.Left)
		r, rNeedsFile, rUsesText := mongoFilter(expr.Right)
		if l == nil || r == nil {
			return nil, false, false
		}
		needsFile := lNeedsFile || rNeedsFile
		usesText := lUsesText || rUsesText
		switch expr.Kind {
		case SearchOr:
			return bson.M{"$or": []bson.M{l, r}}, needsFile, usesText
		case SearchAndNot:
			return bson.M{"$and": []bson.M{l, {"$nor": []bson.M{r}}}}, needsFile, usesText
		default:
			return bson.M{"$and": []bson.M{l, r}}, needsFile, usesText
		}
	default:
		return nil, false, false
	}
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
