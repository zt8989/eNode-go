package natsim

import (
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
