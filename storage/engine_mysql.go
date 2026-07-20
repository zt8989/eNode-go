package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"enode/logging"
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
	// DeadlockDelay is the pause between retries of a deadlocked statement.
	// AddFile touches files and sources in an order two concurrent offers of the
	// same popular file can invert, which InnoDB resolves by killing one of them.
	DeadlockDelay time.Duration
	// DeadlockRetries bounds those retries. Zero means the default below.
	DeadlockRetries int
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
	if cfg.DeadlockDelay <= 0 {
		cfg.DeadlockDelay = defaultDeadlockDelay
	}
	if cfg.DeadlockRetries <= 0 {
		cfg.DeadlockRetries = defaultDeadlockRetries
	}
	return &MySQLEngine{cfg: cfg}, nil
}

const (
	defaultDeadlockDelay   = 100 * time.Millisecond
	defaultDeadlockRetries = 3

	// MySQL error numbers. These are NOT interchangeable:
	//
	//	1213 ER_LOCK_DEADLOCK — InnoDB has already rolled the whole transaction
	//	     back. Safe to retry from the start.
	//	1205 ER_LOCK_WAIT_TIMEOUT — with the default innodb_rollback_on_timeout=OFF
	//	     only the *statement* is rolled back and the transaction stays open and
	//	     partially applied. Retrying it blindly inside a multi-statement
	//	     transaction double-applies the earlier statements.
	//
	// Every statement here runs in autocommit and uses absolute SET values rather
	// than read-modify-write, so re-running one is idempotent and both codes can
	// be retried safely — but only because of that, and the distinction is kept
	// explicit so it survives any future move into a transaction.
	mysqlErrDeadlock        = 1213
	mysqlErrLockWaitTimeout = 1205
)

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
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM clients WHERE online = 1`).Scan(&c); err != nil {
		logging.Errorf("mysql clients count failed: %v", err)
	}
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
	if _, err := m.db.Exec(`UPDATE clients SET online = 0 WHERE id = ?`, info.StoreID); err != nil {
		logging.Errorf("mysql disconnect client storeID=%d failed: %v", info.StoreID, err)
	}
	if _, err := m.db.Exec(`UPDATE sources SET online = 0 WHERE id_client = ?`, info.StoreID); err != nil {
		logging.Errorf("mysql disconnect sources storeID=%d failed: %v", info.StoreID, err)
	}
}

func (m *MySQLEngine) FilesCount() int {
	if err := m.ensureDB(); err != nil {
		return 0
	}
	var c int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM files`).Scan(&c); err != nil {
		logging.Errorf("mysql files count failed: %v", err)
	}
	return c
}

func (m *MySQLEngine) AddFile(file File, clientInfo ClientInfo) {
	if err := m.ensureDB(); err != nil {
		return
	}
	file = NormalizeFile(file)
	err := m.execRetry("add file", func() error {
		_, err := m.db.Exec(
			`INSERT INTO files(hash,size,time_offer) VALUES(?,?,NOW())
			 ON DUPLICATE KEY UPDATE time_offer=NOW()`,
			file.Hash, file.Size,
		)
		return err
	})
	if err != nil {
		logging.Errorf("mysql add file hash=%x size=%d failed: %v", file.Hash, file.Size, err)
		return
	}

	var fileID uint64
	if err := m.execRetry("lookup file id", func() error {
		return m.db.QueryRow(`SELECT id FROM files WHERE hash = ? AND size = ? LIMIT 1`, file.Hash, file.Size).Scan(&fileID)
	}); err != nil {
		logging.Errorf("mysql lookup file id hash=%x size=%d failed: %v", file.Hash, file.Size, err)
		return
	}

	typ := file.Type
	if typ == "" {
		typ = GetFileType(file.Name)
	}
	// Every value below originates in a client tag. NormalizeFile above has
	// already clamped them to the column widths and mapped type into the ENUM;
	// without that, an over-length name/codec or a type such as
	// "EmuleCollection" aborts this INSERT under STRICT_TRANS_TABLES and the
	// file is published but never becomes searchable.
	if err := m.execRetry("add source", func() error {
		_, err := m.db.Exec(
			`INSERT INTO sources(id_file,id_client,name,ext,type,title,artist,album,length,bitrate,codec,online,complete,time_offer)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NOW())
			 ON DUPLICATE KEY UPDATE
			 name=VALUES(name), ext=VALUES(ext), type=VALUES(type), title=VALUES(title),
			 artist=VALUES(artist), album=VALUES(album), length=VALUES(length), bitrate=VALUES(bitrate),
			 codec=VALUES(codec), online=1, complete=VALUES(complete), time_offer=NOW()`,
			fileID, clientInfo.StoreID, file.Name, NormalizeExt(file.Name), typ, file.Title, file.Artist, file.Album,
			file.Runtime, file.Bitrate, file.Codec, 1, boolToTinyInt(file.Completed > 0),
		)
		return err
	}); err != nil {
		logging.Errorf("mysql add source fileID=%d clientID=%d name=%q type=%q failed: %v",
			fileID, clientInfo.StoreID, file.Name, typ, err)
		return
	}

	if err := m.refreshFileCounters(fileID, clientInfo.ID, clientInfo.Port); err != nil {
		logging.Errorf("mysql refresh counters fileID=%d failed: %v", fileID, err)
	}
}

func (m *MySQLEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	if err := m.ensureDB(); err != nil {
		return nil
	}
	rows, err := m.db.Query(
		`SELECT c.id_ed2k, c.port, c.hash
		 FROM sources s
		 INNER JOIN clients c ON c.id = s.id_client
		 INNER JOIN files f ON f.id = s.id_file
		 WHERE f.hash = ? AND f.size = ? AND s.online = 1 AND c.online = 1
		 ORDER BY s.online DESC, s.time_offer DESC
		 LIMIT 255`,
		fileHash, fileSize,
	)
	if err != nil {
		logging.Errorf("mysql get sources hash=%x size=%d failed: %v", fileHash, fileSize, err)
		return nil
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.ID, &s.Port, &s.UserHash); err == nil {
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
		`SELECT c.id_ed2k, c.port, c.hash
		 FROM sources s
		 INNER JOIN clients c ON c.id = s.id_client
		 INNER JOIN files f ON f.id = s.id_file
		 WHERE f.hash = ? AND s.online = 1 AND c.online = 1
		 ORDER BY s.online DESC, s.time_offer DESC
		 LIMIT 255`,
		fileHash,
	)
	if err != nil {
		logging.Errorf("mysql get sources by hash=%x failed: %v", fileHash, err)
		return nil
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.ID, &s.Port, &s.UserHash); err == nil {
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
		logging.Errorf("mysql find by name %q failed: %v", term, err)
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
	// One row per file, carrying metadata from an arbitrary representative
	// source — the semantics the MySQL 5.5 original relied on implicitly.
	//
	// ANY_VALUE() states that explicitly. Without it, ONLY_FULL_GROUP_BY (default
	// since 5.7) rejects the query with ER_1055: grouping is by s.id_file, and
	// sources' only uniqueness covering it is UNIQUE(id_file, id_client), so
	// id_file alone does not determine a source row. The f.* columns need no
	// wrapping — they are functionally dependent through s.id_file = f.id, where
	// f.id is the primary key.
	//
	// Deliberately not fixed by relaxing sql_mode in the DSN: that would also
	// decide STRICT_TRANS_TABLES, silently masking oversized/invalid client tags
	// instead of letting the normalization in NormalizeFile handle them.
	rows, err := m.db.Query(
		`SELECT ANY_VALUE(s.name), f.completed, f.sources, f.hash, f.size, f.source_id, f.source_port,
		        ANY_VALUE(s.type), ANY_VALUE(s.title), ANY_VALUE(s.artist), ANY_VALUE(s.album),
		        ANY_VALUE(s.length), ANY_VALUE(s.bitrate), ANY_VALUE(s.codec)
		 FROM sources s
		 INNER JOIN files f ON s.id_file = f.id
		 WHERE `+where+`
		 GROUP BY s.id_file
		 LIMIT 255`,
		args...,
	)
	if err != nil {
		logging.Errorf("mysql search failed (where=%q): %v", where, err)
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

// CleanupStale removes offline clients and sources older than maxAge.
//
// Without it the index on clients.online only postpones the problem: nothing
// ever deleted a client row, so the table grew monotonically and every count or
// sweep scanned every client the server had ever seen.
func (m *MySQLEngine) CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error) {
	var result CleanupResult
	if err := m.ensureDB(); err != nil {
		return result, err
	}
	if maxAge <= 0 {
		return result, fmt.Errorf("cleanup: maxAge must be positive, got %s", maxAge)
	}
	batch := opts.BatchSize
	if batch <= 0 {
		batch = DefaultCleanupBatchSize
	}
	cutoff := time.Now().Add(-maxAge)

	// Collect the affected files before deleting, so the counters can be
	// recomputed afterwards. Skipping this leaves files.sources permanently
	// overstating reality, and that column feeds both the search filters and the
	// source count advertised in OP_SEARCHRESULT.
	affected, err := m.staleAffectedFileIDs(cutoff)
	if err != nil {
		return result, err
	}

	// Clients first: the sources FK cascades on delete, so this also removes the
	// source rows belonging to every client that goes.
	//
	// online = 1 rows are never touched regardless of age. A long-lived session
	// is not stale, and on MySQL time_login is ON UPDATE CURRENT_TIMESTAMP rather
	// than a liveness signal.
	deleted, err := m.deleteInBatches(
		`DELETE FROM clients WHERE online = 0 AND time_login < ? LIMIT ?`, cutoff, batch)
	if err != nil {
		return result, err
	}
	result.Clients = deleted

	// A second pass for sources whose client is still connected.
	deleted, err = m.deleteInBatches(
		`DELETE FROM sources WHERE online = 0 AND time_offer < ? LIMIT ?`, cutoff, batch)
	if err != nil {
		return result, err
	}
	result.Sources = deleted

	for _, fileID := range affected {
		if err := m.recountFileSources(fileID); err != nil {
			logging.Errorf("mysql cleanup refresh counters fileID=%d failed: %v", fileID, err)
		}
	}

	if !opts.KeepZeroSourceFiles {
		deleted, err = m.deleteInBatches(`DELETE FROM files WHERE sources = 0 LIMIT ?`, nil, batch)
		if err != nil {
			return result, err
		}
		result.Files = deleted
	}
	return result, nil
}

// staleAffectedFileIDs lists the files that will lose at least one source.
func (m *MySQLEngine) staleAffectedFileIDs(cutoff time.Time) ([]uint64, error) {
	rows, err := m.db.Query(
		`SELECT DISTINCT s.id_file FROM sources s
		 LEFT JOIN clients c ON c.id = s.id_client
		 WHERE (s.online = 0 AND s.time_offer < ?)
		    OR (c.online = 0 AND c.time_login < ?)`,
		cutoff, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// deleteInBatches runs a LIMIT-ed DELETE until it stops matching rows.
//
// One unbounded DELETE would hold locks across the whole sources table, which
// AddFile's counter refresh aggregates — straight into the deadlock path that
// execRetry exists to handle. Passing nil for cutoff runs a statement whose only
// placeholder is the limit.
func (m *MySQLEngine) deleteInBatches(query string, cutoff any, batch int) (int, error) {
	total := 0
	for {
		var affected int64
		err := m.execRetry("cleanup delete", func() error {
			var res sql.Result
			var err error
			if cutoff == nil {
				res, err = m.db.Exec(query, batch)
			} else {
				res, err = m.db.Exec(query, cutoff, batch)
			}
			if err != nil {
				return err
			}
			affected, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return total, err
		}
		total += int(affected)
		if int(affected) < batch {
			return total, nil
		}
	}
}

// recountFileSources refreshes only the aggregate counters, leaving source_id
// and source_port alone.
//
// refreshFileCounters cannot be reused here: it also writes the offering
// client's id and port, and a cleanup sweep has no such client — passing zeros
// would wipe the last known source address off every file it touched.
func (m *MySQLEngine) recountFileSources(fileID uint64) error {
	return m.execRetry("recount sources", func() error {
		_, err := m.db.Exec(
			`UPDATE files f
			 LEFT JOIN (
			   SELECT id_file, SUM(complete) AS completed, COUNT(*) AS sources
			   FROM sources WHERE id_file = ? GROUP BY id_file
			 ) s ON s.id_file = f.id
			 SET f.completed = COALESCE(s.completed,0),
			     f.sources = COALESCE(s.sources,0)
			 WHERE f.id = ?`,
			fileID, fileID,
		)
		return err
	})
}

// refreshFileCounters recomputes the denormalized counters for one file.
//
// The aggregate is scoped with `WHERE id_file = ?`. It used to run
// `SELECT ... FROM sources GROUP BY id_file` across the whole table on every
// offered file, holding locks over rows belonging to unrelated files while
// taking an exclusive lock on the parent files row — which is what made
// concurrent offers of one popular file deadlock in the first place.
func (m *MySQLEngine) refreshFileCounters(fileID uint64, sourceID uint32, sourcePort uint16) error {
	return m.execRetry("refresh counters", func() error {
		_, err := m.db.Exec(
			`UPDATE files f
			 LEFT JOIN (
			   SELECT id_file, SUM(complete) AS completed, COUNT(*) AS sources
			   FROM sources WHERE id_file = ? GROUP BY id_file
			 ) s ON s.id_file = f.id
			 SET f.completed = COALESCE(s.completed,0),
			     f.sources = COALESCE(s.sources,0),
			     f.source_id = ?, f.source_port = ?
			 WHERE f.id = ?`,
			fileID, sourceID, sourcePort, fileID,
		)
		return err
	})
}

// execRetry re-runs a statement that InnoDB rejected for lock contention.
//
// Deliberately per statement rather than around all of AddFile: wrapping the
// four statements in one transaction to make retry atomic would hold their locks
// for the whole sequence and make deadlocks *more* likely, not less. Retrying
// individually is safe here only because every statement is idempotent —
// ON DUPLICATE KEY UPDATE with absolute SET values, and a counter refresh that
// recomputes from an aggregate rather than incrementing.
func (m *MySQLEngine) execRetry(what string, fn func() error) error {
	var err error
	for attempt := 0; attempt <= m.cfg.DeadlockRetries; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		if !isRetryableLockError(err) {
			return err
		}
		if attempt < m.cfg.DeadlockRetries {
			logging.Warnf("mysql %s hit lock contention, retrying (attempt %d/%d): %v",
				what, attempt+1, m.cfg.DeadlockRetries, err)
			time.Sleep(m.cfg.DeadlockDelay)
		}
	}
	return fmt.Errorf("%s failed after %d retries: %w", what, m.cfg.DeadlockRetries, err)
}

// isRetryableLockError reports whether MySQL rejected the statement for lock
// contention rather than for anything about its content.
func isRetryableLockError(err error) bool {
	if err == nil {
		return false
	}
	var mysqlErr *mysqldriver.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return mysqlErr.Number == mysqlErrDeadlock || mysqlErr.Number == mysqlErrLockWaitTimeout
}

func boolToTinyInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
