package storage

import "testing"

func TestMemoryEngineClientAndFiles(t *testing.T) {
	m := NewMemoryEngine()
	_ = m.Init()
	c := ClientInfo{ID: 1, Port: 4662}
	if m.IsConnected(c) {
		t.Fatalf("should be disconnected")
	}
	if _, err := m.Connect(c); err != nil {
		t.Fatal(err)
	}
	if !m.IsConnected(c) || m.ClientsCount() != 1 {
		t.Fatalf("connect failed")
	}

	hash := []byte("0123456789abcdef")
	m.AddFile(File{
		Hash: hash, Name: "movie.mkv", Size: 100, SourceID: 1, SourcePort: 4662,
	}, c)
	if m.FilesCount() != 1 {
		t.Fatalf("files count mismatch")
	}
	if len(m.GetSources(hash, 100)) != 1 {
		t.Fatalf("sources mismatch")
	}
	if len(m.FindByNameContains("movie")) != 1 {
		t.Fatalf("find mismatch")
	}
	m.Disconnect(c)
	if m.ClientsCount() != 0 {
		t.Fatalf("disconnect failed")
	}
}
