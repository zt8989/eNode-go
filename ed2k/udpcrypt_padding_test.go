package ed2k

import "testing"

// buildObfsServerUDP crafts a client→server obfuscated datagram with an explicit
// padding-length byte and pad bytes, mirroring eMule's EncryptSendServer layout
// (protocol, randomKey, then RC4(sync | padLen | pad | payload)). The existing
// round-trip helpers always send padLen 0, which cannot exercise L9.
func buildObfsServerUDP(u *UDPCrypt, randomKey uint16, padByte byte, pad, payload []byte) []byte {
	enc := NewBuffer(4 + 1 + len(pad) + len(payload))
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(padByte)
	enc.PutBuffer(pad)
	enc.PutBuffer(payload)
	cipher := RC4Crypt(enc.Bytes(), len(enc.Bytes()), u.rc4Key(MagicValueUDPClientServer, randomKey))

	wire := NewBuffer(3 + len(cipher))
	_ = wire.PutUInt8(0xff) // non-PrED2K marker forces the decrypt path
	_ = wire.PutUInt16LE(randomKey)
	wire.PutBuffer(cipher)
	return wire.Bytes()
}

// TestUDPDecryptMasksAndBoundsPadding pins L9: the padding-length byte is masked to
// its low nibble, and a packet whose remaining bytes cannot cover the declared
// padding is rejected and returned undecoded. eMule does `byPadding[0] &= 0xf` and
// bails when `remaining <= padLen` (EncryptedDatagramSocket.cpp:404-415).
func TestUDPDecryptMasksAndBoundsPadding(t *testing.T) {
	u := NewUDPCrypt(true, 0x11223344)
	payload := []byte{PrED2K, 0xAA, 0xBB}

	// (a) The high nibble on the pad byte must be ignored: 0x32 → 2 pad bytes, not 50.
	pad := []byte{0x77, 0x88}
	wireA := buildObfsServerUDP(u, 0x3344, 0x32, pad, payload)
	t.Logf("input(a): padByte=0x32 (low nibble 2), pad=%d bytes, payload=%d bytes", len(pad), len(payload))
	gotA := u.Decrypt(wireA)
	if string(gotA) != string(payload) {
		t.Fatalf("masking failed: got %v, want payload %v (reverted build skips 0x32=50 bytes)", gotA, payload)
	}
	t.Logf("output(a): payload recovered using masked pad length = %v", gotA)

	// (b) padLen (masked to 15) >= remaining bytes (5) → reject, return input buffer.
	body := []byte{1, 2, 3, 4, 5}
	wireB := buildObfsServerUDP(u, 0x3344, 0xff, nil, body)
	t.Logf("input(b): padByte=0xff (masks to 15), no pad, payload=5 → remaining=5 <= 15")
	gotB := u.Decrypt(wireB)
	if string(gotB) != string(wireB) {
		t.Fatalf("oversized padding not rejected: got %v, want the input buffer unchanged", gotB)
	}
	t.Logf("output(b): oversized padding rejected, buffer returned undecoded (len=%d)", len(gotB))
}
