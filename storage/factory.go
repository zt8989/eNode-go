package storage

import "fmt"

type Config struct {
	Engine  string
	MySQL   MySQLConfig
	MongoDB MongoConfig
}

type Engine interface {
	Init() error
	Close() error
	ClientsCount() int
	IsConnected(ClientInfo) bool
	Connect(ClientInfo) (int, error)
	Disconnect(ClientInfo)
	FilesCount() int
	AddFile(File, ClientInfo)
	GetSources([]byte, uint64) []Source
	GetSourcesByHash([]byte) []Source
	FindByNameContains(string) []File
	ServersCount() int
	AddServer(Server)
	ServersAll() []Server
}

func NewEngine(cfg Config) (Engine, error) {
	switch cfg.Engine {
	case "", "memory":
		return NewMemoryEngine(), nil
	case "mysql":
		return NewMySQLEngine(cfg.MySQL)
	case "mongodb":
		return NewMongoDBEngine(cfg.MongoDB)
	default:
		return nil, fmt.Errorf("unknown storage engine: %s", cfg.Engine)
	}
}
