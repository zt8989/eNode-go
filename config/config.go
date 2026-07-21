package config

import (
	"fmt"
	"os"
	"time"

	"enode/storage"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	Address      string   `yaml:"address"`
	DynIP        string   `yaml:"dynIp"`
	TestURLs     []string `yaml:"testUrls"`
	MessageLowID string   `yaml:"messageLowID"`
	MessageLogin string   `yaml:"messageLogin"`
	// NoAssert is accepted for config compatibility with the Node original but is
	// an intentional no-op: Go bounds-checks every slice/array access, so there is
	// no assertion layer to disable. Kept so an existing YAML with the key loads.
	NoAssert bool   `yaml:"noAssert"`
	LogLevel string `yaml:"logLevel"`
	LogFile  string `yaml:"logFile"`

	// Servers seeds OP_SERVERLIST — the other servers this node advertises to
	// clients (never itself; a server's own identity travels in OP_SERVERIDENT).
	// Empty by default: an empty list is valid and correct, unlike the Node
	// original's two hard-coded invalid placeholder IPs.
	Servers []ServerEntry `yaml:"servers"`

	SupportCrypt bool `yaml:"supportCrypt"`
	RequestCrypt bool `yaml:"requestCrypt"`
	RequireCrypt bool `yaml:"requireCrypt"`
	AuxiliarPort bool `yaml:"auxiliarPort"`
	IPInLogin    bool `yaml:"IPinLogin"`

	TCP TCPConfig `yaml:"tcp"`
	UDP UDPConfig `yaml:"udp"`
	NAT NATConfig `yaml:"natTraversal"`

	Storage StorageConfig `yaml:"storage"`
}

// ServerEntry is one advertised peer server in OP_SERVERLIST.
type ServerEntry struct {
	IP   string `yaml:"ip"`
	Port uint16 `yaml:"port"`
}

type TCPConfig struct {
	Port              uint16 `yaml:"port"`
	PortObfuscated    uint16 `yaml:"portObfuscated"`
	MaxConnections    int    `yaml:"maxConnections"`
	ConnectionTimeout int    `yaml:"connectionTimeout"`
	DisconnectTimeout int    `yaml:"disconnectTimeout"`
	AllowLowIDs       bool   `yaml:"allowLowIDs"`
	MinLowID          uint32 `yaml:"minLowID"`
	MaxLowID          uint32 `yaml:"maxLowID"`
}

type UDPConfig struct {
	Port           uint16 `yaml:"port"`
	PortObfuscated uint16 `yaml:"portObfuscated"`
	GetSources     bool   `yaml:"getSources"`
	GetFiles       bool   `yaml:"getFiles"`
	ServerKey      uint32 `yaml:"serverKey"`
}

type NATConfig struct {
	Enabled                bool   `yaml:"enabled"`
	Port                   uint16 `yaml:"port"`
	RegistrationTTLSeconds int    `yaml:"registrationTTLSeconds"`
}

type StorageConfig struct {
	Engine  string        `yaml:"engine"`
	Cleanup CleanupConfig `yaml:"cleanup"`
	MySQL   MySQLConfig   `yaml:"mysql"`
	MongoDB MongoDBConfig `yaml:"mongodb"`
}

type CleanupConfig struct {
	Enabled         bool `yaml:"enabled"`
	StaleAfterHours int  `yaml:"staleAfterHours"`
	IntervalMinutes int  `yaml:"intervalMinutes"`
	// KeepZeroSourceFiles is a *bool, not a bool, so setDefaults can tell an
	// absent key from an explicit false. A plain bool would default to false when
	// the key is missing — the opposite of the intended default — and would
	// silently start deleting files for anyone whose config predates this option.
	KeepZeroSourceFiles *bool `yaml:"keepZeroSourceFiles"`
	BatchSize           int   `yaml:"batchSize"`
}

// KeepZeroSourceFilesOrDefault reports whether files with no remaining sources
// are retained, defaulting to true.
//
// Kept by default because the server's source list is not the only way a client
// finds peers: Kad and source exchange can locate sources for a file the server
// knows about but currently has none online for. The search result is how a user
// discovers the hash at all, so deleting it removes discovery for no gain.
func (c CleanupConfig) KeepZeroSourceFilesOrDefault() bool {
	if c.KeepZeroSourceFiles == nil {
		return true
	}
	return *c.KeepZeroSourceFiles
}

type MySQLConfig struct {
	Database      string `yaml:"database"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	User          string `yaml:"user"`
	Pass          string `yaml:"pass"`
	Connections   int    `yaml:"connections"`
	DeadlockDelay int    `yaml:"deadlockDelay"`
	// SchemaFile is the DDL applied on first connect when the tables are missing.
	// Relative to the working directory; defaults to misc/enode.sql.
	SchemaFile string `yaml:"schemaFile"`
}

type MongoDBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	URI      string `yaml:"uri"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	setDefaults(&cfg)
	return cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Address == "" {
		cfg.Address = "0.0.0.0"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.LogFile == "" {
		cfg.LogFile = "logs/enode.log"
	}
	if len(cfg.TestURLs) == 0 {
		cfg.TestURLs = []string{
			"https://4.ipw.cn",
			"https://ip.3322.net",
			"https://api.ipify.org",
			"https://checkip.amazonaws.com",
		}
	}
	// Ports match the Node original (enode.config.js) and both shipped YAMLs:
	// TCP 5555/5565 and UDP 5559/5569, preserving the original's tcp+4 relation.
	// The port previously fell back to the classic eDonkey 4661/4662/4665/4666,
	// which no config in the repo uses — so a YAML omitting the port keys bound
	// different ports than every sample config.
	if cfg.TCP.Port == 0 {
		cfg.TCP.Port = 5555
	}
	if cfg.TCP.PortObfuscated == 0 {
		cfg.TCP.PortObfuscated = 5565
	}
	if cfg.TCP.DisconnectTimeout <= 0 {
		cfg.TCP.DisconnectTimeout = 3600
	}
	if cfg.UDP.Port == 0 {
		cfg.UDP.Port = 5559
	}
	if cfg.UDP.PortObfuscated == 0 {
		cfg.UDP.PortObfuscated = 5569
	}
	if cfg.NAT.Port == 0 {
		cfg.NAT.Port = 2004
	}
	if cfg.NAT.RegistrationTTLSeconds <= 0 {
		cfg.NAT.RegistrationTTLSeconds = 30
	}
	if cfg.Storage.Engine == "" {
		cfg.Storage.Engine = "memory"
	}
	if cfg.Storage.Cleanup.StaleAfterHours <= 0 {
		cfg.Storage.Cleanup.StaleAfterHours = 24
	}
	if cfg.Storage.Cleanup.IntervalMinutes <= 0 {
		cfg.Storage.Cleanup.IntervalMinutes = 60
	}
	if cfg.Storage.MySQL.Port == 0 {
		cfg.Storage.MySQL.Port = 3306
	}
	if cfg.Storage.MySQL.SchemaFile == "" {
		cfg.Storage.MySQL.SchemaFile = "misc/enode.sql"
	}
	if cfg.Storage.MongoDB.Port == 0 {
		cfg.Storage.MongoDB.Port = 27017
	}
	if cfg.Storage.MongoDB.Database == "" {
		cfg.Storage.MongoDB.Database = "enode"
	}
}

func (c Config) StorageEngineConfig() storage.Config {
	mysqlCfg := storage.MySQLConfig{
		Host:            c.Storage.MySQL.Host,
		Port:            c.Storage.MySQL.Port,
		User:            c.Storage.MySQL.User,
		Pass:            c.Storage.MySQL.Pass,
		Database:        c.Storage.MySQL.Database,
		MaxOpenConns:    c.Storage.MySQL.Connections,
		MaxIdleConns:    c.Storage.MySQL.Connections / 2,
		ConnMaxLifetime: 5 * time.Minute,
		// deadlockDelay was parsed from YAML and then dropped here, so the option
		// had no effect anywhere in the program.
		DeadlockDelay: time.Duration(c.Storage.MySQL.DeadlockDelay) * time.Millisecond,
		SchemaFile:    c.Storage.MySQL.SchemaFile,
	}
	mongoURI := c.Storage.MongoDB.URI
	if mongoURI == "" {
		mongoURI = fmt.Sprintf("mongodb://%s:%d", c.Storage.MongoDB.Host, c.Storage.MongoDB.Port)
	}
	mongoCfg := storage.MongoConfig{
		URI:      mongoURI,
		Database: c.Storage.MongoDB.Database,
		Timeout:  10 * time.Second,
	}
	return storage.Config{
		Engine:  c.Storage.Engine,
		MySQL:   mysqlCfg,
		MongoDB: mongoCfg,
	}
}
