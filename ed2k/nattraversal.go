package ed2k

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

const (
	DefaultNATTraversalPort = 2004
	defaultNATRegistryTTL   = 10 * time.Minute
	defaultNATCleanupEvery  = time.Minute
)

type NATTraversalConfig struct {
	Enabled                bool
	Port                   uint16
	RegistrationTTLSeconds int
}

type natClientEntry struct {
	hash     [16]byte
	addr     *net.UDPAddr
	lastSeen time.Time
}

type natOutbound struct {
	to     *net.UDPAddr
	packet []byte
}

type NATTraversalHandler struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[[16]byte]natClientEntry
}

func NewNATTraversalHandler(registrationTTL time.Duration) *NATTraversalHandler {
	if registrationTTL <= 0 {
		registrationTTL = defaultNATRegistryTTL
	}
	return &NATTraversalHandler{
		ttl:     registrationTTL,
		entries: map[[16]byte]natClientEntry{},
	}
}

func (h *NATTraversalHandler) HandlePacket(data []byte, remote *net.UDPAddr, conn *net.UDPConn) {
	if len(data) == 0 || remote == nil || conn == nil {
		return
	}
	local, _ := conn.LocalAddr().(*net.UDPAddr)
	for _, out := range h.processPacket(data, remote, local) {
		_, _ = conn.WriteToUDP(out.packet, out.to)
	}
}

func (h *NATTraversalHandler) StartCleanup(interval time.Duration) func() {
	if interval <= 0 {
		interval = defaultNATCleanupEvery
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.cleanup()
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

func (h *NATTraversalHandler) processPacket(data []byte, remote *net.UDPAddr, local *net.UDPAddr) []natOutbound {
	if len(data) == 0 || remote == nil {
		return nil
	}
	if data[0] != PrNat {
		h.touchByAddr(remote)
		return nil
	}
	opcode, payload, ok := decodeNATPacket(data)
	if !ok {
		return nil
	}
	switch opcode {
	case OpNatRegister:
		return h.handleRegister(remote, local, payload)
	case OpNatSync2:
		return h.handleSync2(remote, payload)
	default:
		return nil
	}
}

func (h *NATTraversalHandler) handleRegister(remote *net.UDPAddr, local *net.UDPAddr, payload []byte) []natOutbound {
	if len(payload) < 16 {
		return nil
	}
	var hash [16]byte
	copy(hash[:], payload[:16])
	h.upsert(hash, remote)

	resp := make([]byte, 6)
	if local != nil {
		binary.BigEndian.PutUint16(resp[0:2], uint16(local.Port))
		binary.BigEndian.PutUint32(resp[2:6], ipv4ToUint32(local.IP))
	}
	return []natOutbound{{
		to:     cloneUDPAddr(remote),
		packet: encodeNATPacket(OpNatRegister, resp),
	}}
}

func (h *NATTraversalHandler) handleSync2(remote *net.UDPAddr, payload []byte) []natOutbound {
	if len(payload) < 36 {
		return nil
	}
	var srcHash [16]byte
	var dstHash [16]byte
	copy(srcHash[:], payload[0:16])
	connAck := append([]byte(nil), payload[16:20]...)
	copy(dstHash[:], payload[20:36])

	src, srcOK := h.get(srcHash)
	if !srcOK {
		h.upsert(srcHash, remote)
		src, _ = h.get(srcHash)
	}
	dst, dstOK := h.get(dstHash)
	if !dstOK {
		failed := make([]byte, 17)
		failed[0] = 0x01
		copy(failed[1:], dstHash[:])
		return []natOutbound{{
			to:     cloneUDPAddr(remote),
			packet: encodeNATPacket(OpNatFailed, failed),
		}}
	}
	return []natOutbound{
		{
			to:     cloneUDPAddr(src.addr),
			packet: buildNATSyncPacket(dst.addr, dst.hash, connAck),
		},
		{
			to:     cloneUDPAddr(dst.addr),
			packet: buildNATSyncPacket(src.addr, src.hash, connAck),
		},
	}
}

func buildNATSyncPacket(peer *net.UDPAddr, peerHash [16]byte, connAck []byte) []byte {
	payload := make([]byte, 26)
	if peer != nil {
		binary.BigEndian.PutUint32(payload[0:4], ipv4ToUint32(peer.IP))
		binary.BigEndian.PutUint16(payload[4:6], uint16(peer.Port))
	}
	copy(payload[6:22], peerHash[:])
	copy(payload[22:26], connAck)
	return encodeNATPacket(OpNatSync, payload)
}

func (h *NATTraversalHandler) upsert(hash [16]byte, remote *net.UDPAddr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries[hash] = natClientEntry{
		hash:     hash,
		addr:     cloneUDPAddr(remote),
		lastSeen: time.Now(),
	}
}

func (h *NATTraversalHandler) touchByAddr(remote *net.UDPAddr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for k, v := range h.entries {
		if v.addr.IP.Equal(remote.IP) && v.addr.Port == remote.Port {
			v.lastSeen = now
			h.entries[k] = v
			return
		}
	}
}

func (h *NATTraversalHandler) get(hash [16]byte) (natClientEntry, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	v, ok := h.entries[hash]
	return v, ok
}

func (h *NATTraversalHandler) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().Add(-h.ttl)
	for k, v := range h.entries {
		if v.lastSeen.Before(cutoff) {
			delete(h.entries, k)
		}
	}
}

func encodeNATPacket(opcode uint8, payload []byte) []byte {
	out := make([]byte, 6+len(payload))
	out[0] = PrNat
	binary.LittleEndian.PutUint32(out[1:5], uint32(len(payload)+1))
	out[5] = opcode
	copy(out[6:], payload)
	return out
}

func decodeNATPacket(raw []byte) (uint8, []byte, bool) {
	if len(raw) < 6 || raw[0] != PrNat {
		return 0, nil, false
	}
	sizeWithOpcode := binary.LittleEndian.Uint32(raw[1:5])
	if sizeWithOpcode == 0 {
		return 0, nil, false
	}
	packetEnd := int(sizeWithOpcode) + 5
	if packetEnd > len(raw) {
		return 0, nil, false
	}
	opcode := raw[5]
	payload := append([]byte(nil), raw[6:packetEnd]...)
	return opcode, payload, true
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	ip := append(net.IP(nil), addr.IP...)
	return &net.UDPAddr{IP: ip, Port: addr.Port, Zone: addr.Zone}
}

func ipv4ToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}
