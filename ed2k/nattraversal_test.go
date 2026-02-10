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

	outA := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA)
	outB := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB)
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
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA)
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

	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA); len(got) != 1 {
		t.Fatalf("register A responses len=%d", len(got))
	}
	if got := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB); len(got) != 1 {
		t.Fatalf("register B responses len=%d", len(got))
	}

	connAck := []byte{0xc3, 0x2e, 0x00, 0x15}
	sync2 := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2), remoteA)
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

	_ = handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA)
	connAck := []byte{1, 2, 3, 4}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashUnknown...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA)
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

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote)
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

	outs := handler.processPacket(encodeNATPacket(OpNatRegister, hash), remote)
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
