package ed2k

type LowIDClients struct {
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

func (l *LowIDClients) nextID() (uint32, bool) {
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
	return l.count
}

func (l *LowIDClients) Add(client any) (uint32, bool) {
	id, ok := l.nextID()
	if !ok {
		return 0, false
	}
	l.clients[id] = client
	l.count++
	return id, true
}

func (l *LowIDClients) Get(id uint32) (any, bool) {
	v, ok := l.clients[id]
	return v, ok
}

func (l *LowIDClients) Remove(id uint32) {
	if _, ok := l.clients[id]; ok {
		delete(l.clients, id)
		l.count--
	}
}
