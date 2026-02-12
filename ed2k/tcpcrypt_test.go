package ed2k

import (
	"bytes"
	"math/big"
	"testing"
)

func cloneRC4Key(k *RC4Key) *RC4Key {
	cp := *k
	return &cp
}

func TestTCPCryptNegotiateAndHandshake(t *testing.T) {
	p := NewPacket()
	tc := NewTCPCrypt(p, true)

	g := big.NewInt(2)
	pmod := new(big.Int).SetBytes(CryptPrime)
	A := new(big.Int).Exp(g, big.NewInt(5), pmod).Bytes()
	aBuf := make([]byte, CryptPrimeSize)
	copy(aBuf[CryptPrimeSize-len(A):], A)

	negIn := append([]byte{0x7a}, aBuf...) // random non-protocol marker
	negIn = append(negIn, 0x00)            // pad len = 0
	resp, err := tc.ProcessData(NewBufferFromBytes(negIn))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) <= CryptPrimeSize {
		t.Fatalf("unexpected negotiate response size: %d", len(resp))
	}
	if tc.State != CsNegotiating {
		t.Fatalf("status mismatch after negotiate: %d", tc.State)
	}

	plain := NewBuffer(4 + 1 + 1 + 1)
	_ = plain.PutUInt32LE(MagicValueSync)
	_ = plain.PutUInt8(uint8(EmObfuscate))
	_ = plain.PutUInt8(0)
	plain.PutBuffer([]byte{0x99})

	clientKey := cloneRC4Key(tc.RecvKey)
	wire := RC4Crypt(plain.Bytes(), len(plain.Bytes()), clientKey)
	rest, err := tc.ProcessData(NewBufferFromBytes(wire))
	if err != nil {
		t.Fatal(err)
	}
	if tc.State != CsEncrypting {
		t.Fatalf("status mismatch after handshake: %d", tc.State)
	}
	if !bytes.Equal(rest, []byte{0x99}) {
		t.Fatalf("unexpected remaining payload: %v", rest)
	}
}
