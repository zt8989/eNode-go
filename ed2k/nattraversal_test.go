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
	local := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2004}
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}
	remoteB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40002}

	hashA := bytes.Repeat([]byte{0x11}, 16)
	hashB := bytes.Repeat([]byte{0x22}, 16)

	outA := handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, local)
	outB := handler.processPacket(encodeNATPacket(OpNatRegister, hashB), remoteB, local)
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

	connAck := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashB...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, local)
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

func TestNATSync2TargetNotRegistered(t *testing.T) {
	handler := NewNATTraversalHandler(time.Minute)
	local := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2004}
	remoteA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40001}

	hashA := bytes.Repeat([]byte{0x33}, 16)
	hashUnknown := bytes.Repeat([]byte{0x44}, 16)

	_ = handler.processPacket(encodeNATPacket(OpNatRegister, hashA), remoteA, local)
	connAck := []byte{1, 2, 3, 4}
	sync2Payload := append(append(append([]byte(nil), hashA...), connAck...), hashUnknown...)
	outs := handler.processPacket(encodeNATPacket(OpNatSync2, sync2Payload), remoteA, local)
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
