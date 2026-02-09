package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var (
	ErrMySQLConfigInvalid  = errors.New("mysql config is invalid")
	ErrMySQLNotInitialized = errors.New("mysql engine is not initialized")
)

type MySQLConfig struct {
	Host            string
	Port            int
	User            string
	Pass            string
	Database        string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type MySQLEngine struct {
	cfg     MySQLConfig
	db      *sql.DB
	servers []Server
}

func NewMySQLEngine(cfg MySQLConfig) (*MySQLEngine, error) {
	if cfg.Host == "" || cfg.User == "" || cfg.Database == "" || cfg.Port <= 0 {
		return nil, ErrMySQLConfigInvalid
	}
	if cfg.MaxOpenConns <= 0 {
		cfg.MaxOpenConns = 10
	}
	if cfg.MaxIdleConns < 0 {
		cfg.MaxIdleConns = 0
	}
	if cfg.ConnMaxLifetime <= 0 {
		cfg.ConnMaxLifetime = 5 * time.Minute
	}
	return &MySQLEngine{cfg: cfg}, nil
}

func (m *MySQLEngine) dsn() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4,utf8&collation=utf8mb4_unicode_ci",
		m.cfg.User, m.cfg.Pass, m.cfg.Host, m.cfg.Port, m.cfg.Database)
}

func (m *MySQLEngine) ensureDB() error {
	if m.db == nil {
		return ErrMySQLNotInitialized
	}
	return nil
}

func (m *MySQLEngine) Init() error {
	db, err := sql.Open("mysql", m.dsn())
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(m.cfg.MaxOpenConns)
	db.SetMaxIdleConns(m.cfg.MaxIdleConns)
	db.SetConnMaxLifetime(m.cfg.ConnMaxLifetime)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE clients SET online = 0`); err != nil {
		_ = db.Close()
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE sources SET online = 0`); err != nil {
		_ = db.Close()
		return err
	}
	m.db = db
	return nil
}

func (m *MySQLEngine) Close() error {
	if m.db == nil {
		return nil
	}
	return m.db.Close()
}

func (m *MySQLEngine) ClientsCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	var c int
	_ = m.db.QueryRow(`SELECT COUNT(*) FROM clients WHERE online = 1`).Scan(&c)
	return c
}

func (m *MySQLEngine) IsConnected(info ClientInfo) bool {
	if err := m.ensureDB(); err != nil {
		return false
	}
	var id uint64
	err := m.db.QueryRow(`SELECT id FROM clients WHERE hash = ? AND online = 1 LIMIT 1`, info.Hash).Scan(&id)
	return err == nil
}

func (m *MySQLEngine) Connect(info ClientInfo) (int, error) {
	if err := m.ensureDB(); err != nil {
		return 0, err
	}
	_, err := m.db.Exec(
		`INSERT INTO clients(hash, id_ed2k, ipv4, port, online) VALUES(?,?,?,?,1)
		 ON DUPLICATE KEY UPDATE id_ed2k=VALUES(id_ed2k), ipv4=VALUES(ipv4), port=VALUES(port), online=1`,
		info.Hash, info.ID, info.IPv4, info.Port,
	)
	if err != nil {
		return 0, err
	}
	var id int
	if err := m.db.QueryRow(`SELECT id FROM clients WHERE hash = ? LIMIT 1`, info.Hash).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (m *MySQLEngine) Disconnect(info ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	_, _ = m.db.Exec(`UPDATE clients SET online = 0 WHERE id = ?`, info.StoreID)
	_, _ = m.db.Exec(`UPDATE sources SET online = 0 WHERE id_client = ?`, info.StoreID)
}

func (m *MySQLEngine) FilesCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	var c int
	_ = m.db.QueryRow(`SELECT COUNT(*) FROM files`).Scan(&c)
	return c
}

func (m *MySQLEngine) AddFile(file File, clientInfo ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	_, err := m.db.Exec(
		`INSERT INTO files(hash,size,time_offer) VALUES(?,?,NOW())
		 ON DUPLICATE KEY UPDATE time_offer=NOW()`,
		file.Hash, file.Size,
	)
	if err != nil {
		return
	}

	var fileID uint64
	if err := m.db.QueryRow(`SELECT id FROM files WHERE hash = ? AND size = ? LIMIT 1`, file.Hash, file.Size).Scan(&fileID); err != nil {
		return
	}

	typ := file.Type
	if typ == "" {
		typ = GetFileType(file.Name)
	}
	_, _ = m.db.Exec(
		`INSERT INTO sources(id_file,id_client,name,ext,type,title,artist,album,length,bitrate,codec,online,complete,time_offer)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())
		 ON DUPLICATE KEY UPDATE
		 name=VALUES(name), ext=VALUES(ext), type=VALUES(type), title=VALUES(title),
		 artist=VALUES(artist), album=VALUES(album), length=VALUES(length), bitrate=VALUES(bitrate),
		 codec=VALUES(codec), online=1, complete=VALUES(complete), time_offer=NOW()`,
		fileID, clientInfo.StoreID, file.Name, Ext(file.Name), typ, file.Title, file.Artist, file.Album,
		file.Runtime, file.Bitrate, file.Codec, 1, boolToTinyInt(file.Completed > 0),
	)

	_, _ = m.db.Exec(
		`UPDATE files f
		 LEFT JOIN (
		   SELECT id_file, SUM(complete) AS completed, COUNT(*) AS sources
		   FROM sources GROUP BY id_file
		 ) s ON s.id_file = f.id
		 SET f.completed = COALESCE(s.completed,0),
		     f.sources = COALESCE(s.sources,0),
		     f.source_id = ?, f.source_port = ?
		 WHERE f.id = ?`,
		clientInfo.ID, clientInfo.Port, fileID,
	)
}

func (m *MySQLEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	rows, err := m.db.Query(
		`SELECT c.id_ed2k, c.port
		 FROM sources s
		 INNER JOIN clients c ON c.id = s.id_client
		 INNER JOIN files f ON f.id = s.id_file
		 WHERE f.hash = ? AND f.size = ?
		 ORDER BY s.online DESC, s.time_offer DESC
		 LIMIT 255`,
		fileHash, fileSize,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.ID, &s.Port); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func (m *MySQLEngine) GetSourcesByHash(fileHash []byte) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	rows, err := m.db.Query(
		`SELECT c.id_ed2k, c.port
		 FROM sources s
		 INNER JOIN clients c ON c.id = s.id_client
		 INNER JOIN files f ON f.id = s.id_file
		 WHERE f.hash = ?
		 ORDER BY s.online DESC, s.time_offer DESC
		 LIMIT 255`,
		fileHash,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.ID, &s.Port); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func (m *MySQLEngine) FindByNameContains(term string) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	rows, err := m.db.Query(
		`SELECT s.name, f.completed, f.sources, f.hash, f.size, f.source_id, f.source_port,
		        s.type, s.title, s.artist, s.album, s.length, s.bitrate, s.codec
		 FROM sources s
		 INNER JOIN files f ON s.id_file = f.id
		 WHERE s.name LIKE ?
		 ORDER BY s.time_offer DESC
		 LIMIT 255`,
		"%"+term+"%",
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		var typ string
		if err := rows.Scan(&f.Name, &f.Completed, &f.Sources, &f.Hash, &f.Size, &f.SourceID, &f.SourcePort,
			&typ, &f.Title, &f.Artist, &f.Album, &f.Runtime, &f.Bitrate, &f.Codec); err == nil {
			f.Type = typ
			out = append(out, f)
		}
	}
	return out
}

func (m *MySQLEngine) FindBySearch(expr *SearchExpr) []File {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	where, args := BuildSearchWhere(expr)
	if where == "" {
		return nil
	}
	rows, err := m.db.Query(
		`SELECT s.name, f.completed, f.sources, f.hash, f.size, f.source_id, f.source_port,
		        s.type, s.title, s.artist, s.album, s.length, s.bitrate, s.codec
		 FROM sources s
		 INNER JOIN files f ON s.id_file = f.id
		 WHERE `+where+`
		 GROUP BY s.id_file
		 LIMIT 255`,
		args...,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		var typ string
		if err := rows.Scan(&f.Name, &f.Completed, &f.Sources, &f.Hash, &f.Size, &f.SourceID, &f.SourcePort,
			&typ, &f.Title, &f.Artist, &f.Album, &f.Runtime, &f.Bitrate, &f.Codec); err == nil {
			f.Type = typ
			out = append(out, f)
		}
	}
	return out
}

func (m *MySQLEngine) ServersCount() int {
	return len(m.servers)
}

func (m *MySQLEngine) AddServer(server Server) {
	m.servers = append(m.servers, server)
}

func (m *MySQLEngine) ServersAll() []Server {
	return append([]Server(nil), m.servers...)
}

func boolToTinyInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
