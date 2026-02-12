package ed2k

import (
	"encoding/binary"
	"hash/fnv"
	"sync"
)

type LowIDClients struct {
	mu          sync.Mutex
	min         uint32
	max         uint32
	count       uint32
	allowLowIDs bool
	clients     map[uint32]any
}

func NewLowIDClients(allowLowIDs bool) *LowIDClients {
	return &LowIDClients{
		min:         1,
		max:         0xffffff,
		allowLowIDs: allowLowIDs,
		clients:     map[uint32]any{},
	}
}

func (l *LowIDClients) rangeSizeLocked() uint32 {
	return l.max - l.min + 1
}

func (l *LowIDClients) addByKeyLocked(key []byte, client any) (uint32, bool) {
	if !l.allowLowIDs {
		return 0, false
	}
	if l.count >= l.rangeSizeLocked() {
		return 0, false
	}
	for nonce := uint32(0); nonce < l.rangeSizeLocked(); nonce++ {
		id := l.hashToLowIDLocked(key, nonce)
		if _, ok := l.clients[id]; ok {
			continue
		}
		l.clients[id] = client
		l.count++
		return id, true
	}
	return 0, false
}

func (l *LowIDClients) hashToLowIDLocked(key []byte, nonce uint32) uint32 {
	h := fnv.New32a()
	_, _ = h.Write(key)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], nonce)
	_, _ = h.Write(b[:])
	raw := h.Sum32() & 0x00ffffff
	span := l.rangeSizeLocked()
	return l.min + (raw % span)
}

func (l *LowIDClients) Count() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

func (l *LowIDClients) Add(client any) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Backward-compatible fallback for generic callers/tests.
	return l.addByKeyLocked([]byte("lowid-default-seed"), client)
}

func (l *LowIDClients) AddByEndpoint(ipv4 uint32, port uint16, client any) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var key [6]byte
	binary.LittleEndian.PutUint32(key[0:4], ipv4)
	binary.LittleEndian.PutUint16(key[4:6], port)
	return l.addByKeyLocked(key[:], client)
}

func (l *LowIDClients) Get(id uint32) (any, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.clients[id]
	return v, ok
}

func (l *LowIDClients) Remove(id uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.clients[id]; ok {
		delete(l.clients, id)
		l.count--
	}
}
