package ed2k

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestNATRegisterAndSync2(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("1.2.3.4", 2004)
	local := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2004}
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)

	outA := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, uint16(local.Port))
	outB := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, uint16(local.Port))
	if len(outA) != 1 || len(outB) != 1 {
		t.Fatalf("register responses mismatch")
	}

	_, payloadA, ok := decodeNATPacket(outA[0].packet)
	if !ok {
		t.Fatalf("bad register packet for A")
	}
	_, payloadB, ok := decodeNATPacket(outB[0].packet)
	if !ok {
		t.Fatalf("bad register packet for B")
	}
	if binary.BigEndian.Uint16(payloadA[0:2]) != uint16(local.Port) {
		t.Fatalf("bad register port A")
	}
	if binary.BigEndian.Uint16(payloadB[0:2]) != uint16(local.Port) {
		t.Fatalf("bad register port B")
	}
	if binary.BigEndian.Uint32(payloadA[2:6]) != binary.BigEndian.Uint32(net.ParseIP("1.2.3.4").To4()) {
		t.Fatalf("bad register ip A")
	}
	if binary.BigEndian.Uint32(payloadB[2:6]) != binary.BigEndian.Uint32(net.ParseIP("1.2.3.4").To4()) {
		t.Fatalf("bad register ip B")
	}

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, uint16(local.Port))
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}

	for _, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("bad sync packet")
		}
		if opcode != OpNatSync {
			t.Fatalf("bad opcode %#x", opcode)
		}
		if len(payload) != 26 {
			t.Fatalf("bad payload len=%d", len(payload))
		}
		switch out.to.Port {
		case remoteA.Port:
			if !bytes.Equal(payload[6:22], hashB) {
				t.Fatalf("A packet peer hash mismatch")
			}
			if binary.BigEndian.Uint16(payload[4:6]) != uint16(remoteB.Port) {
				t.Fatalf("A packet peer port mismatch")
			}
		case remoteB.Port:
			if !bytes.Equal(payload[6:22], hashA) {
				t.Fatalf("B packet peer hash mismatch")
			}
			if binary.BigEndian.Uint16(payload[4:6]) != uint16(remoteA.Port) {
				t.Fatalf("B packet peer port mismatch")
			}
		default:
			t.Fatalf("unexpected target port %d", out.to.Port)
		}
		if !bytes.Equal(payload[22:26], connAck) {
			t.Fatalf("connAck mismatch")
		}
	}
}

func TestNATSync2AfterBothRegisteredReturnsNatSync(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.10.0.1"), Port: 31001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.10.0.2"), Port: 31002}

	hashA := []byte{0x46, 0xa7, 0xde, 0xd3, 0x6e, 0x0e, 0xd3, 0xba, 0xbd, 0x84, 0x02, 0xea, 0x5d, 0xfe, 0x6f, 0x7e}
	hashB := []byte{0xe9, 0x27, 0x88, 0xe7, 0x52, 0x0e, 0x75, 0x3c, 0xb6, 0x74, 0xb2, 0xdf, 0x37, 0x45, 0x6f, 0x9f}

	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, 2004); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	connAck := []byte{0xc3, 0x2e, 0x00, 0x15}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), remoteA, 2004)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}

	for i, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("decode out[%d] failed", i)
		}
		if opcode != OpNatSync {
			t.Fatalf("out[%d] opcode=%#x want=%#x", i, opcode, OpNatSync)
		}
		if len(payload) != 26 {
			t.Fatalf("out[%d] payload len=%d", i, len(payload))
		}
	}
}

func TestNATSync2TargetNotRegistered(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}

	hashA := bytes.Repeat([]byte{0x33}, 16)
	hashUnknown := bytes.Repeat([]byte{0x44}, 16)

	_ = handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, 2004)
	connAck := []byte{1, 2, 3, 4}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashUnknown...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, 2004)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}

	opcode, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok {
		t.Fatalf("bad nat failed packet")
	}
	if opcode != OpNatFailed {
		t.Fatalf("opcode=%#x", opcode)
	}
	if len(payload) != 17 {
		t.Fatalf("payload len=%d", len(payload))
	}
	if payload[0] != 0x01 {
		t.Fatalf("reason=%d", payload[0])
	}
	if !bytes.Equal(payload[1:], hashUnknown) {
		t.Fatalf("target hash mismatch")
	}
}

func TestNATRegisterUsesConfiguredEndpoint(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("66.154.127.95", 2004)

	// local is wildcard; response should still use configured public endpoint.
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x55}, 16)

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}
	_, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok || len(payload) != 6 {
		t.Fatalf("bad register ack")
	}

	wantIP := binary.BigEndian.Uint32(net.ParseIP("66.154.127.95").To4())
	gotPort := binary.BigEndian.Uint16(payload[0:2])
	gotIP := binary.BigEndian.Uint32(payload[2:6])
	if gotPort != 2004 {
		t.Fatalf("port=%d", gotPort)
	}
	if gotIP != wantIP {
		t.Fatalf("ip=%d want=%d", gotIP, wantIP)
	}
}

func TestNATRegisterWildcardLocalWithoutConfiguredEndpoint(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)

	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x66}, 16)

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}
	_, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok || len(payload) != 6 {
		t.Fatalf("bad register ack")
	}

	// Without configured endpoint and wildcard bind, response IP is 0.0.0.0.
	gotIP := binary.BigEndian.Uint32(payload[2:6])
	if gotIP != 0 {
		t.Fatalf("ip=%d want=0", gotIP)
	}
}

func TestNATRegisterUsesObfuscatedPortByLocalListener(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("66.154.127.95", 2004)
	handler.SetRegisterEndpointForLocalPort(5559, 5559)

	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x77}, 16)

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 5559)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}
	_, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok || len(payload) != 6 {
		t.Fatalf("bad register ack")
	}
	gotPort := binary.BigEndian.Uint16(payload[0:2])
	if gotPort != 5559 {
		t.Fatalf("port=%d want=5559", gotPort)
	}
}

func TestNATRegisterOnNatPortReturnsPlainUDPPort(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("66.154.127.95", 4665)
	handler.SetRegisterEndpointForLocalPort(2004, 4665)
	handler.SetRegisterEndpointForLocalPort(5559, 5559)

	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0x7a}, 16)

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("responses len=%d", len(outs))
	}
	_, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok || len(payload) != 6 {
		t.Fatalf("bad register ack")
	}
	gotPort := binary.BigEndian.Uint16(payload[0:2])
	if gotPort != 4665 {
		t.Fatalf("port=%d want=4665", gotPort)
	}
}

func TestNATSync2ReturnsSyncExToRegisterExClient(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0xa1}, 16)
	hashB := bytes.Repeat([]byte{0xb2}, 16)

	registerA := append(append([]byte(nil), hashA...), byte(1))
	if got := handler.processPacket(encodeNATPacket(OpNatRegisterEx, registerA), remoteA, 2004); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	connAck := []byte{0x12, 0x34, 0x56, 0x78}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, 2004)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}

	for _, out := range outs {
		opcode, payload, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("decode sync response failed")
		}
		switch out.to.Port {
		case remoteA.Port:
			if opcode != OpNatSyncEx {
				t.Fatalf("A opcode=%#x want=%#x", opcode, OpNatSyncEx)
			}
			if len(payload) != 27 {
				t.Fatalf("A payload len=%d want=27", len(payload))
			}
			if payload[26] != 0 {
				t.Fatalf("A peer version=%d want=0", payload[26])
			}
		case remoteB.Port:
			if opcode != OpNatSync {
				t.Fatalf("B opcode=%#x want=%#x", opcode, OpNatSync)
			}
			if len(payload) != 26 {
				t.Fatalf("B payload len=%d want=26", len(payload))
			}
		default:
			t.Fatalf("unexpected target port %d", out.to.Port)
		}
	}
}

func TestNATRegisterWithLegacyStatsKeepsSyncOpcode(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0xc1}, 16)
	hashB := bytes.Repeat([]byte{0xd2}, 16)
	legacyStats := []byte{0x00, 0x03, 0x00, 0x04, 0x00, 0x05}
	registerA := append(append([]byte(nil), hashA...), legacyStats...)
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, registerA), remoteA, 2004); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 2004); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, 2004)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}
	for _, out := range outs {
		opcode, _, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("decode sync response failed")
		}
		if opcode != OpNatSync {
			t.Fatalf("opcode=%#x want=%#x", opcode, OpNatSync)
		}
	}
}

func TestNATEntriesSharedAcrossAllListenerPorts(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	handler.SetRegisterEndpoint("66.154.127.95", 2004)
	handler.SetRegisterEndpointForLocalPort(5559, 5559) // udp obfuscated

	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0x88}, 16)
	hashB := bytes.Repeat([]byte{0x99}, 16)

	// Register A from natTraversal.port (example: 2004)
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, 2004); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	// Register B from udp.portObfuscated (example: 5559)
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, 5559); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	// Send sync2 from udp.port and ensure cross-port registry lookup succeeds.
	connAck := []byte{0x12, 0x34, 0x56, 0x78}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, 5555)
	if len(outs) != 2 {
		t.Fatalf("sync2 responses len=%d", len(outs))
	}
	for i, out := range outs {
		opcode, _, ok := decodeNATPacket(out.packet)
		if !ok {
			t.Fatalf("decode out[%d] failed", i)
		}
		if opcode != OpNatSync {
			t.Fatalf("out[%d] opcode=%#x want=%#x", i, opcode, OpNatSync)
		}
	}
}

func TestNATKeepaliveOneByteRefreshesLastSeen(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0xaa}, 16)

	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004); len(got) != 1 {
		t.Fatalf("register responses len=%d", len(got))
	}
	var key [16]byte
	copy(key[:], hash)
	entryBefore, ok := handler.get(key)
	if !ok {
		t.Fatalf("entry not found after register")
	}

	time.Sleep(5 * time.Millisecond)
	outs := handler.processPacket([]byte{0x42}, remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("keepalive responses len=%d", len(outs))
	}
	opcode, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok {
		t.Fatalf("decode keepalive response failed")
	}
	if opcode != OpNatPing {
		t.Fatalf("keepalive response opcode=%#x want=%#x", opcode, OpNatPing)
	}
	if len(payload) != 0 {
		t.Fatalf("keepalive response payload len=%d want=0", len(payload))
	}

	entryAfter, ok := handler.get(key)
	if !ok {
		t.Fatalf("entry missing after keepalive")
	}
	if !entryAfter.lastSeen.After(entryBefore.lastSeen) {
		t.Fatalf("lastSeen not refreshed: before=%v after=%v", entryBefore.lastSeen, entryAfter.lastSeen)
	}
}

func TestNATKeepaliveOpcodeRefreshesLastSeen(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	hash := bytes.Repeat([]byte{0xbb}, 16)

	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote, 2004); len(got) != 1 {
		t.Fatalf("register responses len=%d", len(got))
	}
	var key [16]byte
	copy(key[:], hash)
	entryBefore, ok := handler.get(key)
	if !ok {
		t.Fatalf("entry not found after register")
	}

	time.Sleep(5 * time.Millisecond)
	outs := handler.processPacket(encodeNATPacket(OpNatKeepAlive, nil), remote, 2004)
	if len(outs) != 1 {
		t.Fatalf("nat keepalive responses len=%d", len(outs))
	}
	opcode, payload, ok := decodeNATPacket(outs[0].packet)
	if !ok {
		t.Fatalf("decode nat keepalive response failed")
	}
	if opcode != OpNatPing {
		t.Fatalf("nat keepalive response opcode=%#x want=%#x", opcode, OpNatPing)
	}
	if len(payload) != 0 {
		t.Fatalf("nat keepalive response payload len=%d want=0", len(payload))
	}

	entryAfter, ok := handler.get(key)
	if !ok {
		t.Fatalf("entry missing after nat keepalive")
	}
	if !entryAfter.lastSeen.After(entryBefore.lastSeen) {
		t.Fatalf("lastSeen not refreshed: before=%v after=%v", entryBefore.lastSeen, entryAfter.lastSeen)
	}
}

func TestNATKeepaliveUnregisteredClientNoPing(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	remote := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 40009}

	if got := handler.processPacket([]byte{0x42}, remote, 2004); len(got) != 0 {
		t.Fatalf("legacy keepalive for unregistered client should not respond, len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatKeepAlive, nil), remote, 2004); len(got) != 0 {
		t.Fatalf("nat keepalive for unregistered client should not respond, len=%d", len(got))
	}
}
