package ed2k

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"enode/logging"
)

const (
	DefaultNATTraversalPort = 2004
	defaultNATRegistryTTL   = 30 * time.Second
	defaultNATCleanupEvery  = 10 * time.Second
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
	mu                  sync.RWMutex
	ttl                 time.Duration
	entries             map[[16]byte]natClientEntry
	announceIPv4        uint32
	announcePort        uint16
	announcePortByLocal map[uint16]uint16
}

func NewNATTraversalHandler(registrationTTL time.Duration) *NATTraversalHandler {
	if registrationTTL <= 0 {
		registrationTTL = defaultNATRegistryTTL
	}
	return &NATTraversalHandler{
		ttl:                 registrationTTL,
		entries:             map[[16]byte]natClientEntry{},
		announcePortByLocal: map[uint16]uint16{},
	}
}

// ConfigureRegisterEndpointFromConfig stores dynIp/address hints used by HandlePacket.
// Priority is dynIp first, then address.
func (h *NATTraversalHandler) ConfigureRegisterEndpointFromConfig(dynIP, address string, port uint16) {
	if h == nil {
		return
	}
	ip := dynIP
	if ip == "" {
		ip = address
	}
	h.SetRegisterEndpoint(ip, port)
}

// SetRegisterEndpoint sets the endpoint returned in OP_NAT_REGISTER ACK.
// If ip is empty/invalid, handler falls back to local socket address.
func (h *NATTraversalHandler) SetRegisterEndpoint(ip string, port uint16) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.announceIPv4 = 0
	h.announcePort = 0
	if parsed := net.ParseIP(ip); parsed != nil {
		h.announceIPv4 = ipv4ToUint32(parsed)
	}
	if port != 0 {
		h.announcePort = port
	}
}

// SetRegisterEndpointForLocalPort overrides the OP_NAT_REGISTER ACK port
// based on the local listener port which received the registration packet.
func (h *NATTraversalHandler) SetRegisterEndpointForLocalPort(localPort uint16, announcePort uint16) {
	if h == nil || localPort == 0 || announcePort == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.announcePortByLocal == nil {
		h.announcePortByLocal = map[uint16]uint16{}
	}
	h.announcePortByLocal[localPort] = announcePort
}

func (h *NATTraversalHandler) HandlePacket(data []byte, remote *net.UDPAddr, conn *net.UDPConn) {
	if len(data) == 0 || remote == nil || conn == nil {
		return
	}
	if data[0] == PrNat {
		LogNATRaw("nat", "recv", remote.String(), data)
	}
	localPort := uint16(0)
	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && localAddr != nil && localAddr.Port > 0 {
		localPort = uint16(localAddr.Port)
	}
	for _, out := range h.processPacket(data, remote, localPort) {
		target := ""
		if out.to != nil {
			target = out.to.String()
		}
		if len(out.packet) > 0 && out.packet[0] == PrNat {
			LogNATRaw("nat", "send", target, out.packet)
		}
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

func (h *NATTraversalHandler) processPacket(data []byte, remote *net.UDPAddr, localPort uint16) []natOutbound {
	if len(data) == 0 || remote == nil {
		return nil
	}
	if len(data) == 1 {
		matched := h.touchByAddr(remote)
		logging.Debugf(
			"[module=nat] dir=recv, remote=%s, opcode=KEEPALIVE(1-byte), value=0x%02x, matched=%t",
			remote.String(), data[0], matched,
		)
		return nil
	}
	if data[0] != PrNat {
		return nil
	}
	opcode, payload, ok := decodeNATPacket(data)
	if !ok {
		return nil
	}
	switch opcode {
	case OpNatRegister:
		return h.handleRegister(remote, payload, localPort)
	case OpNatKeepAlive:
		matched := h.touchByAddr(remote)
		logging.Debugf(
			"[module=nat] dir=recv, remote=%s, opcode=%s, payloadLen=%d, matched=%t",
			remote.String(), natOpcodeLabel(OpNatKeepAlive), len(payload), matched,
		)
		return nil
	case OpNatSync2:
		return h.handleSync2(remote, payload)
	default:
		return nil
	}
}

func (h *NATTraversalHandler) handleRegister(remote *net.UDPAddr, payload []byte, localPort uint16) []natOutbound {
	if len(payload) < 16 {
		return nil
	}
	var hash [16]byte
	copy(hash[:], payload[:16])
	h.upsert(hash, remote)

	resp := make([]byte, 6)
	h.mu.RLock()
	port := h.announcePort
	if p, ok := h.announcePortByLocal[localPort]; ok && p != 0 {
		port = p
	}
	ipv4 := h.announceIPv4
	h.mu.RUnlock()
	binary.BigEndian.PutUint16(resp[0:2], port)
	binary.BigEndian.PutUint32(resp[2:6], ipv4)
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
	logging.Debugf(
		"[module=nat] dir=recv, remote=%s, opcode=%s, srcHash=%x, srcFound=%t, srcAddr=%s, dstHash=%x, dstFound=%t, dstAddr=%s, registrySize=%d, ttlSec=%d",
		remote.String(),
		natOpcodeLabel(OpNatSync2),
		srcHash[:],
		srcOK,
		formatUDPAddr(src.addr),
		dstHash[:],
		dstOK,
		formatUDPAddr(dst.addr),
		h.entryCount(),
		int(h.ttl/time.Second),
	)
	if !dstOK {
		failed := make([]byte, 17)
		failed[0] = 0x01
		copy(failed[1:], dstHash[:])
		logging.Debugf(
			"[module=nat] dir=send, remote=%s, opcode=%s, reason=dst-not-registered, reasonCode=0x01, targetHash=%x, registry=%s",
			remote.String(),
			natOpcodeLabel(OpNatFailed),
			dstHash[:],
			h.registrySummary(8),
		)
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

func (h *NATTraversalHandler) touchByAddr(remote *net.UDPAddr) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for k, v := range h.entries {
		if v.addr.IP.Equal(remote.IP) && v.addr.Port == remote.Port {
			v.lastSeen = now
			h.entries[k] = v
			return true
		}
	}
	return false
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

func (h *NATTraversalHandler) entryCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

func (h *NATTraversalHandler) registrySummary(limit int) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.entries) == 0 {
		return "[]"
	}
	if limit <= 0 {
		limit = len(h.entries)
	}
	now := time.Now()
	var b strings.Builder
	b.WriteString("[")
	i := 0
	for hash, entry := range h.entries {
		if i > 0 {
			b.WriteString("; ")
		}
		ageSec := int(now.Sub(entry.lastSeen).Seconds())
		if ageSec < 0 {
			ageSec = 0
		}
		b.WriteString(fmt.Sprintf("hash=%x addr=%s ageSec=%d", hash[:], formatUDPAddr(entry.addr), ageSec))
		i++
		if i >= limit {
			if len(h.entries) > limit {
				b.WriteString("; ...")
			}
			break
		}
	}
	b.WriteString("]")
	return b.String()
}

func formatUDPAddr(addr *net.UDPAddr) string {
	if addr == nil {
		return "-"
	}
	return addr.String()
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

func natOpcodeLabel(opcode uint8) string {
	switch opcode {
	case OpNatRegister:
		return "OP_NATREGISTER(0xe4)"
	case OpNatSync2:
		return "OP_NATSYNC2(0xe9)"
	case OpNatSync:
		return "OP_NATSYNC(0xe1)"
	case OpNatFailed:
		return "OP_NATFAILED(0xe5)"
	case OpNatKeepAlive:
		return "OP_NATKEEPALIVE(0xe6)"
	case OpNatPing:
		return "OP_NATPING(0xe2)"
	case OpNatReping:
		return "OP_NATREPING(0xe8)"
	case OpNatData:
		return "OP_NATDATA(0xea)"
	case OpNatAck:
		return "OP_NATACK(0xeb)"
	case OpNatRst:
		return "OP_NATRST(0xef)"
	default:
		return fmt.Sprintf("0x%02x", opcode)
	}
}

func formatNATPayload(opcode uint8, payload []byte) string {
	switch opcode {
	case OpNatRegister:
		if len(payload) >= 16 {
			out := fmt.Sprintf("hash=%x", payload[:16])
			if len(payload) > 16 {
				out += fmt.Sprintf(" extraLen=%d extraHex=%s", len(payload)-16, hex.EncodeToString(payload[16:]))
			}
			return out
		}
		if len(payload) == 6 {
			port := binary.BigEndian.Uint16(payload[0:2])
			ipv4 := binary.BigEndian.Uint32(payload[2:6])
			return fmt.Sprintf("serverPort=%d serverIP=%d serverIPv4=%s", port, ipv4, uint32ToIPv4BE(ipv4))
		}
		return fmt.Sprintf("payloadLen=%d hex=%s", len(payload), hex.EncodeToString(payload))
	case OpNatSync2:
		if len(payload) >= 36 {
			return fmt.Sprintf("srcHash=%x connAck=%x dstHash=%x", payload[0:16], payload[16:20], payload[20:36])
		}
	case OpNatSync:
		if len(payload) >= 26 {
			ipv4 := binary.BigEndian.Uint32(payload[0:4])
			port := binary.BigEndian.Uint16(payload[4:6])
			return fmt.Sprintf("peerIP=%d peerIPv4=%s peerPort=%d peerHash=%x connAck=%x",
				ipv4, uint32ToIPv4BE(ipv4), port, payload[6:22], payload[22:26])
		}
	case OpNatFailed:
		if len(payload) >= 17 {
			return fmt.Sprintf("reason=0x%02x targetHash=%x", payload[0], payload[1:17])
		}
	case OpNatKeepAlive:
		return fmt.Sprintf("payloadLen=%d", len(payload))
	}
	previewLen := len(payload)
	if previewLen > 64 {
		previewLen = 64
	}
	return fmt.Sprintf("payloadLen=%d previewHex=%s", len(payload), hex.EncodeToString(payload[:previewLen]))
}

func uint32ToIPv4BE(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
