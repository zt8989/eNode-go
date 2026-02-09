package ed2k

import (
	"bytes"
	"testing"
)

func TestRC4RoundTrip(t *testing.T) {
	plain := []byte("hello-world")
	k1 := RC4CreateKey([]byte("secret"), true)
	cipher := RC4Crypt(plain, len(plain), k1)
	k2 := RC4CreateKey([]byte("secret"), true)
	decoded := RC4Crypt(cipher, len(cipher), k2)
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("rc4 decode mismatch: %q", decoded)
	}
}

func TestMD5(t *testing.T) {
	got := MD5([]byte("abc"))
	expected := []byte{
		0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
		0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("md5 mismatch: %x", got)
	}
}

func TestRandBufAndProtocol(t *testing.T) {
	buf, err := RandBuf(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != 32 {
		t.Fatalf("randbuf size mismatch: %d", len(buf))
	}
	p := RandProtocol()
	if IsProtocol(p) {
		t.Fatalf("rand protocol should usually be invalid, got valid: 0x%x", p)
	}
}
