package storage

import (
	"bytes"
	"sync"
)

type ClientInfo struct {
	ID      uint32
	IPv4    uint32
	Port    uint16
	Hash    []byte
	LowID   bool
	StoreID int
}

type Source struct {
	ID   uint32
	Port uint16
}

type File struct {
	Hash       []byte
	Name       string
	Size       uint64
	Type       string
	Sources    uint32
	Completed  uint32
	Title      string
	Artist     string
	Album      string
	Runtime    uint32
	Bitrate    uint32
	Codec      string
	SourceID   uint32
	SourcePort uint16
}

type Server struct {
	IP   string
	Port uint16
}

type MemoryEngine struct {
	mu           sync.RWMutex
	nextClientID int
	clients      map[uint32]ClientInfo
	files        map[string]File
	sources      map[string][]Source
	servers      []Server
}

func NewMemoryEngine() *MemoryEngine {
	return &MemoryEngine{
		clients: map[uint32]ClientInfo{},
		files:   map[string]File{},
		sources: map[string][]Source{},
	}
}

func hashKey(hash []byte) string {
	return string(hash)
}

func (m *MemoryEngine) Init() error {
	return nil
}

func (m *MemoryEngine) Close() error {
	return nil
}

func (m *MemoryEngine) ClientsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clients)
}

func (m *MemoryEngine) IsConnected(info ClientInfo) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.clients[info.ID]
	return ok
}

func (m *MemoryEngine) Connect(info ClientInfo) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextClientID++
	info.StoreID = m.nextClientID
	m.clients[info.ID] = info
	return info.StoreID, nil
}

func (m *MemoryEngine) Disconnect(info ClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, info.ID)
}

func (m *MemoryEngine) FilesCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.files)
}

func (m *MemoryEngine) AddFile(file File, clientInfo ClientInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := hashKey(file.Hash)
	m.files[k] = file
	src := Source{ID: clientInfo.ID, Port: clientInfo.Port}
	existing := m.sources[k]
	for _, s := range existing {
		if s.ID == src.ID && s.Port == src.Port {
			return
		}
	}
	m.sources[k] = append(existing, src)
}

func (m *MemoryEngine) GetSources(fileHash []byte, fileSize uint64) []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k := hashKey(fileHash)
	f, ok := m.files[k]
	if !ok || f.Size != fileSize {
		return nil
	}
	out := append([]Source(nil), m.sources[k]...)
	return out
}

func (m *MemoryEngine) GetSourcesByHash(fileHash []byte) []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]Source(nil), m.sources[hashKey(fileHash)]...)
	return out
}

func (m *MemoryEngine) FindByNameContains(term string) []File {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []File
	for _, f := range m.files {
		if term == "" || bytes.Contains([]byte(f.Name), []byte(term)) {
			out = append(out, f)
		}
	}
	return out
}

func (m *MemoryEngine) FindBySearch(expr *SearchExpr) []File {
	if expr == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]File, 0, 32)
	for _, f := range m.files {
		if MatchSearchExpr(expr, f) {
			out = append(out, f)
			if len(out) >= 255 {
				break
			}
		}
	}
	return out
}

func (m *MemoryEngine) ServersCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.servers)
}

func (m *MemoryEngine) AddServer(server Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.servers = append(m.servers, server)
}

func (m *MemoryEngine) ServersAll() []Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Server(nil), m.servers...)
}
