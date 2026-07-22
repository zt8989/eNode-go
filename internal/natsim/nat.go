package natsim

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"enode/ed2k"
)

type SyncInfo struct {
	PeerIP   net.IP
	PeerPort uint16
	PeerHash [16]byte
	ConnAck  [4]byte
	// PeerVersion / HasVersion are set only for the OP_NAT_SYNC_EX form (27-byte
	// payload, peer version appended at [26]). HasVersion==true therefore means
	// the server answered with SYNC_EX rather than the plain 26-byte SYNC.
	PeerVersion uint8
	HasVersion  bool
}

func EncodeNATPacket(opcode uint8, payload []byte) []byte {
	out := make([]byte, 6+len(payload))
	out[0] = ed2k.PrNat
	binary.LittleEndian.PutUint32(out[1:5], uint32(len(payload)+1))
	out[5] = opcode
	copy(out[6:], payload)
	return out
}

func DecodeNATPacket(raw []byte) (uint8, []byte, bool) {
	if len(raw) < 6 || raw[0] != ed2k.PrNat {
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

func BuildSync2Payload(srcHash [16]byte, connAck [4]byte, dstHash [16]byte) []byte {
	payload := make([]byte, 36)
	copy(payload[0:16], srcHash[:])
	copy(payload[16:20], connAck[:])
	copy(payload[20:36], dstHash[:])
	return payload
}

func DecodeSyncPayload(payload []byte) (SyncInfo, bool) {
	if len(payload) < 26 {
		return SyncInfo{}, false
	}
	var info SyncInfo
	info.PeerIP = net.IPv4(payload[0], payload[1], payload[2], payload[3])
	info.PeerPort = binary.BigEndian.Uint16(payload[4:6])
	copy(info.PeerHash[:], payload[6:22])
	copy(info.ConnAck[:], payload[22:26])
	if len(payload) >= 27 {
		info.PeerVersion = payload[26]
		info.HasVersion = true
	}
	return info, true
}

// DecodeSyncPayloadV6 decodes an OP_NAT_SYNC_IPV6 payload (39 bytes):
// [ipv6:16][port:2 BE][hash:16][connAck:4][version:1]. The peer version is always
// present (0 when the peer registered without one), so HasVersion is always true.
func DecodeSyncPayloadV6(payload []byte) (SyncInfo, bool) {
	if len(payload) < 39 {
		return SyncInfo{}, false
	}
	var info SyncInfo
	info.PeerIP = append(net.IP(nil), payload[0:16]...)
	info.PeerPort = binary.BigEndian.Uint16(payload[16:18])
	copy(info.PeerHash[:], payload[18:34])
	copy(info.ConnAck[:], payload[34:38])
	info.PeerVersion = payload[38]
	info.HasVersion = true
	return info, true
}

// BuildRegisterPacket encodes an OP_NAT_REGISTER (hash only) or, when ex is
// true, an OP_NAT_REGISTER_EX carrying the client version byte after the hash.
// Registering with ex>version 0 is what makes the server answer this client
// with OP_NAT_SYNC_EX instead of the plain OP_NAT_SYNC.
func BuildRegisterPacket(hash [16]byte, ex bool, version uint8) []byte {
	if ex {
		payload := make([]byte, 17)
		copy(payload[:16], hash[:])
		payload[16] = version
		return EncodeNATPacket(ed2k.OpNatRegisterEx, payload)
	}
	return EncodeNATPacket(ed2k.OpNatRegister, hash[:])
}

func ParseHashHex(value string) ([16]byte, error) {
	var out [16]byte
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return out, errors.New("hash is empty")
	}
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return out, fmt.Errorf("decode hash hex: %w", err)
	}
	if len(decoded) != len(out) {
		return out, fmt.Errorf("hash must be 16 bytes (32 hex chars), got %d", len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}

func RandConnAck() [4]byte {
	var out [4]byte
	_, err := rand.Read(out[:])
	if err != nil {
		now := uint32(0x12345678)
		binary.LittleEndian.PutUint32(out[:], now)
	}
	return out
}

func HexDump(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return hex.EncodeToString(data)
}
