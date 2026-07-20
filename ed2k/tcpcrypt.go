package ed2k

import (
	"errors"
	"math/big"
	"sync"
)

const (
	MagicValueServer    = 203
	MagicValueRequester = 34
)

// TCPCrypt owns the obfuscation state machine for one connection.
//
// state/sendKey/recvKey are guarded by mu because they are read from goroutines
// other than the one driving the connection: writeRaw is reachable from the
// status ticker and from a peer's OP_CALLBACKREQUEST, while only the owning
// goroutine advances the state machine. RC4 is a stateful stream cipher, so a
// torn read of the key corrupts the rest of the stream, not just one packet.
type TCPCrypt struct {
	Packet *Packet

	mu      sync.RWMutex
	state   int
	sendKey *RC4Key
	recvKey *RC4Key
}

func NewTCPCrypt(packet *Packet, supportCrypt bool) *TCPCrypt {
	status := CsNone
	if supportCrypt {
		status = CsUnknown
	}
	return &TCPCrypt{Packet: packet, state: status}
}

func (t *TCPCrypt) ProcessData(buffer *Buffer) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Packet.Data = NewBufferFromBytes(buffer.Get())
	switch t.state {
	case CsNone:
		return nil, nil
	case CsUnknown:
		resp, err := t.negotiate()
		if err != nil {
			return nil, err
		}
		t.Packet.Status = PsCryptNegotiating
		t.state = CsNegotiating
		return resp, nil
	case CsNegotiating:
		rest, err := t.handshake(buffer.Bytes())
		if err != nil {
			return nil, err
		}
		t.state = CsEncrypting
		t.Packet.Status = PsNew
		return rest, nil
	default:
		return nil, errors.New("unexpected crypt status")
	}
}

func (t *TCPCrypt) State() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.state
}

func (t *TCPCrypt) SetState(state int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = state
}

// SendCipher returns the send key, and whether the stream is encrypting. Both
// are read under one lock: a caller that checked the state separately could
// pair a stale state with a freshly rotated key.
func (t *TCPCrypt) SendCipher() (*RC4Key, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sendKey, t.state == CsEncrypting
}

// RecvCipher mirrors SendCipher for the receive direction.
func (t *TCPCrypt) RecvCipher() (*RC4Key, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.recvKey, t.state == CsEncrypting
}

func (t *TCPCrypt) StatusValue() int {
	return t.State()
}

func (t *TCPCrypt) CryptStatus() int {
	return t.State()
}

func (t *TCPCrypt) negotiate() ([]byte, error) {
	g := big.NewInt(2)
	p := new(big.Int).SetBytes(CryptPrime)
	// Obfuscated incoming stream starts with 1-byte non-protocol marker.
	if _, err := t.Packet.Data.GetUInt8(); err != nil {
		return nil, err
	}
	aBytes := t.Packet.Data.Get(CryptPrimeSize)
	if len(aBytes) != CryptPrimeSize {
		return nil, ErrOutOfBounds
	}
	A := new(big.Int).SetBytes(aBytes)
	bRaw, err := RandBuf(CryptDhaSize)
	if err != nil {
		return nil, err
	}
	b := new(big.Int).SetBytes(bRaw)

	B := new(big.Int).Exp(g, b, p)
	K := new(big.Int).Exp(A, b, p)

	padSize, err := t.Packet.Data.GetUInt8()
	if err != nil {
		return nil, err
	}
	_ = t.Packet.Data.Get(int(padSize))

	kBuf := make([]byte, CryptPrimeSize+1)
	kBytes := K.Bytes()
	copy(kBuf[CryptPrimeSize-len(kBytes):CryptPrimeSize], kBytes)

	kBuf[CryptPrimeSize] = MagicValueServer
	t.sendKey = RC4CreateKey(MD5(kBuf), true)
	kBuf[CryptPrimeSize] = MagicValueRequester
	t.recvKey = RC4CreateKey(MD5(kBuf), true)

	pad, err := RandBuf(Rand(16))
	if err != nil {
		return nil, err
	}

	rc4Buf := NewBuffer(4 + 1 + 1 + 1 + len(pad))
	_ = rc4Buf.PutUInt32LE(MagicValueSync)
	_ = rc4Buf.PutUInt8(uint8(EmSupported))
	_ = rc4Buf.PutUInt8(uint8(EmPreferred))
	_ = rc4Buf.PutUInt8(uint8(len(pad)))
	rc4Buf.PutBuffer(pad)
	enc := RC4Crypt(rc4Buf.Bytes(), len(rc4Buf.Bytes()), t.sendKey)

	BBytes := B.Bytes()
	bout := make([]byte, CryptPrimeSize)
	copy(bout[CryptPrimeSize-len(BBytes):], BBytes)
	return append(bout, enc...), nil
}

// handshake is called from ProcessData with t.mu already held, so it reads the
// guarded fields directly rather than through the accessors.
func (t *TCPCrypt) handshake(buffer []byte) ([]byte, error) {
	if t.state != CsNegotiating {
		return nil, errors.New("bad crypt status")
	}
	data := RC4Crypt(buffer, len(buffer), t.recvKey)
	b := NewBufferFromBytes(data)
	sync, err := b.GetUInt32LE()
	if err != nil {
		return nil, err
	}
	if sync != MagicValueSync {
		return nil, errors.New("wrong MAGICVALUE_SYNC")
	}
	method, err := b.GetUInt8()
	if err != nil {
		return nil, err
	}
	if method != uint8(EmObfuscate) {
		return nil, errors.New("encryption method not supported")
	}
	padLen, err := b.GetUInt8()
	if err != nil {
		return nil, err
	}
	_ = b.Get(int(padLen))
	return b.Get(), nil
}

func (t *TCPCrypt) Decrypt(buffer []byte) []byte {
	if key, encrypting := t.RecvCipher(); encrypting {
		return RC4Crypt(buffer, len(buffer), key)
	}
	return buffer
}

func (t *TCPCrypt) ProcessForPacket(buffer *Buffer) error {
	_, err := t.ProcessData(buffer)
	return err
}

func (t *TCPCrypt) Process(buffer *Buffer) error {
	_, err := t.ProcessData(buffer)
	return err
}
