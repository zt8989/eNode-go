package natsim

import (
	"net"
	"sync"

	"enode/ed2k"
)

type EndpointStore struct {
	mu       sync.RWMutex
	endpoint *net.UDPAddr
}

func NewEndpointStore(initial *net.UDPAddr) *EndpointStore {
	s := &EndpointStore{}
	if initial != nil {
		s.Set(initial)
	}
	return s
}

func (s *EndpointStore) Set(addr *net.UDPAddr) {
	if s == nil || addr == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endpoint = cloneUDPAddr(addr)
}

func (s *EndpointStore) Get() *net.UDPAddr {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneUDPAddr(s.endpoint)
}

func (s *EndpointStore) GetOr(fallback *net.UDPAddr) *net.UDPAddr {
	if ep := s.Get(); ep != nil {
		return ep
	}
	return cloneUDPAddr(fallback)
}

func ParseRegisterEndpoint(payload []byte) (*net.UDPAddr, bool) {
	if len(payload) < 6 {
		return nil, false
	}
	port := int(payload[0])<<8 | int(payload[1])
	ip := net.IPv4(payload[2], payload[3], payload[4], payload[5])
	return &net.UDPAddr{
		IP:   append(net.IP(nil), ip...),
		Port: port,
	}, true
}

func DispatchNATPacket(
	raw []byte,
	onRegister func(endpoint *net.UDPAddr, payload []byte),
	onSync func(info SyncInfo, payload []byte),
	onFailed func(payload []byte),
) bool {
	opcode, payload, ok := DecodeNATPacket(raw)
	if !ok {
		return false
	}
	switch opcode {
	case ed2k.OpNatRegister:
		if endpoint, ok := ParseRegisterEndpoint(payload); ok && onRegister != nil {
			onRegister(endpoint, payload)
		}
	case ed2k.OpNatSync:
		if info, ok := DecodeSyncPayload(payload); ok && onSync != nil {
			onSync(info, payload)
		}
	case ed2k.OpNatFailed:
		if onFailed != nil {
			onFailed(payload)
		}
	}
	return true
}

func IsPing(data []byte) bool {
	return len(data) == 4 && string(data) == "PING"
}

func IsPong(data []byte) bool {
	return len(data) == 4 && string(data) == "PONG"
}

func SendPong(conn *net.UDPConn, remote *net.UDPAddr) error {
	_, err := conn.WriteToUDP([]byte("PONG"), remote)
	return err
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}
