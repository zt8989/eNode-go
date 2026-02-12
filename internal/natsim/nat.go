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
	return info, true
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
