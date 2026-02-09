package storage

import "testing"

func TestNewEngine(t *testing.T) {
	e, err := NewEngine(Config{Engine: "memory"})
	if err != nil || e == nil {
		t.Fatalf("memory engine create failed: %v", err)
	}
	if _, err := NewEngine(Config{Engine: "mysql", MySQL: MySQLConfig{}}); err == nil {
		t.Fatalf("expected mysql config error")
	}
	if _, err := NewEngine(Config{Engine: "mongodb", MongoDB: MongoConfig{}}); err == nil {
		t.Fatalf("expected mongodb config error")
	}
	if _, err := NewEngine(Config{Engine: "unknown"}); err == nil {
		t.Fatalf("expected unknown engine error")
	}
}
