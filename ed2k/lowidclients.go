package ed2k

import "sync"

type LowIDClients struct {
	mu          sync.Mutex
	min         uint32
	max         uint32
	count       uint32
	next        uint32
	allowLowIDs bool
	clients     map[uint32]any
}

func NewLowIDClients(allowLowIDs bool) *LowIDClients {
	return &LowIDClients{
		min:         1,
		max:         0xffffff,
		next:        1,
		allowLowIDs: allowLowIDs,
		clients:     map[uint32]any{},
	}
}

func (l *LowIDClients) nextIDLocked() (uint32, bool) {
	if !l.allowLowIDs {
		return 0, false
	}
	if l.count >= (l.max - l.min + 1) {
		return 0, false
	}
	r := l.next
	l.next++
	for {
		if l.next > l.max {
			l.next = l.min
		}
		if _, ok := l.clients[l.next]; !ok {
			break
		}
		l.next++
	}
	return r, true
}

func (l *LowIDClients) Count() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

func (l *LowIDClients) Add(client any) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id, ok := l.nextIDLocked()
	if !ok {
		return 0, false
	}
	l.clients[id] = client
	l.count++
	return id, true
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
