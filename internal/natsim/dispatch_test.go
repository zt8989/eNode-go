package natsim

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"enode/ed2k"
)

// TestDispatchRoutesOpNatPing proves the OP_NAT_PING keepalive ACK now reaches
// its own callback (feature 2) and no other.
func TestDispatchRoutesOpNatPing(t *testing.T) {
	packet := EncodeNATPacket(ed2k.OpNatPing, nil)
	t.Logf("input: OP_NAT_PING packet = %s", HexDump(packet))

	var natPing, other int
	ok := DispatchNATPacket(
		packet,
		func(*net.UDPAddr, []byte) { other++ },
		func(SyncInfo, []byte) { other++ },
		func([]byte) { other++ },
		func([]byte) { natPing++ },
	)

	t.Logf("output: decoded=%t natPing=%d other=%d", ok, natPing, other)
	if !ok {
		t.Fatalf("DispatchNATPacket returned ok=false for a valid OP_NAT_PING")
	}
	if natPing != 1 || other != 0 {
		t.Fatalf("routing wrong: natPing=%d other=%d, want 1/0", natPing, other)
	}
}

// TestDispatchNilOnNatPing confirms a nil onNatPing is tolerated (no panic).
func TestDispatchNilOnNatPing(t *testing.T) {
	packet := EncodeNATPacket(ed2k.OpNatPing, nil)
	t.Logf("input: OP_NAT_PING packet = %s (nil onNatPing)", HexDump(packet))
	ok := DispatchNATPacket(packet, nil, nil, nil, nil)
	t.Logf("output: decoded=%t", ok)
	if !ok {
		t.Fatalf("DispatchNATPacket returned ok=false")
	}
}

// TestDecodeSyncPayloadVersions covers both the 26-byte OP_NAT_SYNC and the
// 27-byte OP_NAT_SYNC_EX forms (feature 1 decode side).
func TestDecodeSyncPayloadVersions(t *testing.T) {
	base := func() []byte {
		p := make([]byte, 26)
		copy(p[0:4], net.IPv4(1, 2, 3, 4).To4())
		binary.BigEndian.PutUint16(p[4:6], 4662)
		for i := 0; i < 16; i++ {
			p[6+i] = byte(i + 1)
		}
		copy(p[22:26], []byte{0xaa, 0xbb, 0xcc, 0xdd})
		return p
	}

	t.Run("sync_26_no_version", func(t *testing.T) {
		payload := base()
		t.Logf("input: 26-byte SYNC payload = %s", HexDump(payload))
		info, ok := DecodeSyncPayload(payload)
		t.Logf("output: ok=%t peer=%s:%d connAck=%x hasVersion=%t", ok, info.PeerIP, info.PeerPort, info.ConnAck, info.HasVersion)
		if !ok || info.HasVersion {
			t.Fatalf("26-byte SYNC: ok=%t hasVersion=%t, want true/false", ok, info.HasVersion)
		}
		if info.PeerPort != 4662 || !info.PeerIP.Equal(net.IPv4(1, 2, 3, 4)) {
			t.Fatalf("peer decode wrong: %s:%d", info.PeerIP, info.PeerPort)
		}
	})

	t.Run("syncex_27_with_version", func(t *testing.T) {
		payload := append(base(), 0x07) // SYNC_EX appends the peer version byte
		t.Logf("input: 27-byte SYNC_EX payload = %s", HexDump(payload))
		info, ok := DecodeSyncPayload(payload)
		t.Logf("output: ok=%t hasVersion=%t peerVersion=%d", ok, info.HasVersion, info.PeerVersion)
		if !ok || !info.HasVersion || info.PeerVersion != 7 {
			t.Fatalf("27-byte SYNC_EX: ok=%t hasVersion=%t peerVersion=%d, want true/true/7", ok, info.HasVersion, info.PeerVersion)
		}
	})
}

// TestDecodeSyncPayloadV6 decodes the 39-byte OP_NAT_SYNC_IPV6 payload:
// [ipv6:16][port:2 BE][hash:16][connAck:4][version:1].
func TestDecodeSyncPayloadV6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1234").To16()
	hash := bytes.Repeat([]byte{0xab}, 16)
	payload := append([]byte(nil), ip...)
	payload = append(payload, 0x13, 0x88) // port 5000 BE
	payload = append(payload, hash...)
	payload = append(payload, 0xde, 0xad, 0xbe, 0xef) // connAck
	payload = append(payload, 0x07)                   // version

	t.Logf("input: %d-byte SYNC_IPV6 payload = %s", len(payload), HexDump(payload))
	info, ok := DecodeSyncPayloadV6(payload)
	t.Logf("output: ok=%t peerIP=%s port=%d hash=%x connAck=%x version=%d hasVersion=%t",
		ok, info.PeerIP, info.PeerPort, info.PeerHash, info.ConnAck, info.PeerVersion, info.HasVersion)
	if !ok {
		t.Fatalf("decode failed")
	}
	if !info.PeerIP.Equal(net.ParseIP("2001:db8::1234")) {
		t.Fatalf("peerIP=%s want 2001:db8::1234", info.PeerIP)
	}
	if info.PeerPort != 5000 {
		t.Fatalf("port=%d want 5000", info.PeerPort)
	}
	if !bytes.Equal(info.PeerHash[:], hash) {
		t.Fatalf("hash %x want %x", info.PeerHash, hash)
	}
	if info.PeerVersion != 7 || !info.HasVersion {
		t.Fatalf("version=%d hasVersion=%t want 7/true", info.PeerVersion, info.HasVersion)
	}
	if !bytes.Equal(info.ConnAck[:], []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("connAck=%x", info.ConnAck)
	}
	// A short payload is rejected.
	if _, ok := DecodeSyncPayloadV6(payload[:38]); ok {
		t.Fatalf("38-byte payload should not decode as SYNC_IPV6")
	}
}

// TestBuildRegisterPacket round-trips both register forms (feature 1 encode side).
func TestBuildRegisterPacket(t *testing.T) {
	var hash [16]byte
	for i := range hash {
		hash[i] = byte(0xf0 + i)
	}

	t.Run("legacy", func(t *testing.T) {
		packet := BuildRegisterPacket(hash, false, 9) // version ignored when !ex
		t.Logf("input: hash=%x ex=false; packet=%s", hash, HexDump(packet))
		op, payload, ok := DecodeNATPacket(packet)
		t.Logf("output: opcode=%#x payloadLen=%d", op, len(payload))
		if !ok || op != ed2k.OpNatRegister || len(payload) != 16 {
			t.Fatalf("legacy register: ok=%t op=%#x len=%d, want true/%#x/16", ok, op, len(payload), ed2k.OpNatRegister)
		}
		if [16]byte(payload) != hash {
			t.Fatalf("hash mismatch: %x", payload)
		}
	})

	t.Run("ex_with_version", func(t *testing.T) {
		packet := BuildRegisterPacket(hash, true, 3)
		t.Logf("input: hash=%x ex=true version=3; packet=%s", hash, HexDump(packet))
		op, payload, ok := DecodeNATPacket(packet)
		t.Logf("output: opcode=%#x payloadLen=%d version=%d", op, len(payload), payload[len(payload)-1])
		if !ok || op != ed2k.OpNatRegisterEx || len(payload) != 17 {
			t.Fatalf("ex register: ok=%t op=%#x len=%d, want true/%#x/17", ok, op, len(payload), ed2k.OpNatRegisterEx)
		}
		if payload[16] != 3 {
			t.Fatalf("version byte = %d, want 3", payload[16])
		}
	})
}
