package ed2k

import "testing"

func TestUDPCryptRoundTrip(t *testing.T) {
	u := NewUDPCrypt(true, 0x11223344)
	plain := []byte{PrED2K, 0x01, 0x02, 0x03}
	randomKey := uint16(0x3344)

	enc := NewBuffer(len(plain) + 5)
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(0)
	enc.PutBuffer(plain)
	cipher := RC4Crypt(enc.Bytes(), len(enc.Bytes()), u.rc4Key(MagicValueUDPClientServer, randomKey))

	wire := NewBuffer(3 + len(cipher))
	_ = wire.PutUInt8(0xff) // invalid protocol to trigger decrypt
	_ = wire.PutUInt16LE(randomKey)
	wire.PutBuffer(cipher)

	got := u.Decrypt(wire.Bytes())
	if string(got) != string(plain) {
		t.Fatalf("udp decrypt mismatch: %v != %v", got, plain)
	}
}

func TestUDPCryptDisabled(t *testing.T) {
	u := NewUDPCrypt(false, 0)
	plain := []byte{1, 2, 3}
	got := u.Encrypt(plain)
	if string(got) != string(plain) {
		t.Fatalf("encrypt should pass through")
	}
}

func TestUDPCryptDecryptMarkerCollisionWithProtocolByte(t *testing.T) {
	u := NewUDPCrypt(true, 0x55667788)
	plain := []byte{PrED2K, 0x99, 0x01}
	randomKey := uint16(0x1122)

	enc := NewBuffer(len(plain) + 5)
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(0)
	enc.PutBuffer(plain)
	cipher := RC4Crypt(enc.Bytes(), len(enc.Bytes()), u.rc4Key(MagicValueUDPClientServer, randomKey))

	wire := NewBuffer(3 + len(cipher))
	_ = wire.PutUInt8(PrEMule) // marker byte collides with known protocol value
	_ = wire.PutUInt16LE(randomKey)
	wire.PutBuffer(cipher)

	got := u.Decrypt(wire.Bytes())
	if string(got) != string(plain) {
		t.Fatalf("udp decrypt mismatch with marker collision: %v != %v", got, plain)
	}
}
