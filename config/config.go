package config

import (
	"fmt"
	"os"
	"time"

	"enode/storage"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Name         string `yaml:"name"`
	Description  string `yaml:"description"`
	Address      string `yaml:"address"`
	DynIP        string `yaml:"dynIp"`
	MessageLowID string `yaml:"messageLowID"`
	MessageLogin string `yaml:"messageLogin"`
	NoAssert     bool   `yaml:"noAssert"`
	LogLevel     string `yaml:"logLevel"`
	LogFile      string `yaml:"logFile"`

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
	MySQL   MySQLConfig   `yaml:"mysql"`
	MongoDB MongoDBConfig `yaml:"mongodb"`
}

type MySQLConfig struct {
	Database      string `yaml:"database"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	User          string `yaml:"user"`
	Pass          string `yaml:"pass"`
	Connections   int    `yaml:"connections"`
	DeadlockDelay int    `yaml:"deadlockDelay"`
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
	if cfg.TCP.Port == 0 {
		cfg.TCP.Port = 4661
	}
	if cfg.TCP.PortObfuscated == 0 {
		cfg.TCP.PortObfuscated = 4662
	}
	if cfg.TCP.DisconnectTimeout <= 0 {
		cfg.TCP.DisconnectTimeout = 3600
	}
	if cfg.UDP.Port == 0 {
		cfg.UDP.Port = 4665
	}
	if cfg.UDP.PortObfuscated == 0 {
		cfg.UDP.PortObfuscated = 4666
	}
	if cfg.NAT.Port == 0 {
		cfg.NAT.Port = 2004
	}
	if cfg.NAT.RegistrationTTLSeconds <= 0 {
		cfg.NAT.RegistrationTTLSeconds = 600
	}
	if cfg.Storage.Engine == "" {
		cfg.Storage.Engine = "memory"
	}
	if cfg.Storage.MySQL.Port == 0 {
		cfg.Storage.MySQL.Port = 3306
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
