package storage

import "testing"

func TestEngineConstructorsValidateConfig(t *testing.T) {
	if _, err := NewMySQLEngine(MySQLConfig{}); err == nil {
		t.Fatalf("expected mysql config error")
	}
	if _, err := NewMongoDBEngine(MongoConfig{}); err == nil {
		t.Fatalf("expected mongodb config error")
	}
}
