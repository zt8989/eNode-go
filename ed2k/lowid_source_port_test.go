package ed2k

import (
	"encoding/binary"
	"testing"

	"enode/storage"
)

// sourcePortAt reads the 2-byte port of the first source record.
// protocol(1) size(4) opcode(1) hash(16) count(1) id(4) => port at 27.
func sourcePortAt(t *testing.T, packet *Buffer) uint16 {
	t.Helper()
	raw := packet.Bytes()
	if len(raw) < 29 {
		t.Fatalf("packet too short: %d bytes", len(raw))
	}
	return binary.LittleEndian.Uint16(raw[27:29])
}

// OP_FOUNDSOURCES_OBFU replaced a LowID source's port with 0xFFFF. No such
// sentinel exists in eMule: DownloadQueue.cpp reads the port and hands it
// straight to UpDownClient(port, userId, ...), which assigns m_userPort before
// it looks at LowID at all.
//
// The damage is downstream rather than local. KnownFile.cpp and PartFile.cpp
// republish GetUserPort() via source exchange, so the fake port spreads to peers
// that never talked to this server; and ClientList/DeadSourceList key clients on
// (IP, port), so the same peer arriving through both paths never deduplicates.
// Downloads still work — LowID goes via server callback, which ignores the port
// — which is why this corrupted data silently.
func TestFoundSourcesObfuSendsRealLowIDPort(t *testing.T) {
	fileHash := []byte("0123456789abcdef")

	cases := []struct {
		name string
		src  storage.Source
	}{
		{"LowID source", storage.Source{ID: 0x00ABCDEF, Port: 4662}},
		{"HighID source", storage.Source{ID: 0x0100007F, Port: 4662}},
		{"LowID source with a user hash", storage.Source{
			ID: 0x00000123, Port: 12345, UserHash: []byte("fedcba9876543210"),
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain, err := BuildFoundSourcesPacket(fileHash, []storage.Source{tc.src})
			if err != nil {
				t.Fatal(err)
			}
			obfu, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{tc.src})
			if err != nil {
				t.Fatal(err)
			}

			plainPort := sourcePortAt(t, plain)
			obfuPort := sourcePortAt(t, obfu)
			t.Logf("input: id=0x%08x port=%d lowID=%t", tc.src.ID, tc.src.Port, isLowID(tc.src.ID))
			t.Logf("output: OP_FOUNDSOURCES port=%d OP_FOUNDSOURCES_OBFU port=%d", plainPort, obfuPort)

			if obfuPort != tc.src.Port {
				t.Fatalf("obfu port is %d, want the real port %d", obfuPort, tc.src.Port)
			}
			// The two opcodes describe the same peer, so a client that learns it
			// through both must see one identity.
			if obfuPort != plainPort {
				t.Fatalf("obfu port %d differs from plain port %d for the same source", obfuPort, plainPort)
			}
		})
	}
}

// Guard the rest of the obfu layout: one options byte per source, plus a 16-byte
// user hash only when bit 0x80 is set — which the builder sets only for a
// crypt-capable source (N2), tying the hash to advertised crypt support.
func TestFoundSourcesObfuLayoutUnchanged(t *testing.T) {
	fileHash := []byte("0123456789abcdef")
	src := storage.Source{ID: 0x00ABCDEF, Port: 4662}

	plain, err := BuildFoundSourcesPacket(fileHash, []storage.Source{src})
	if err != nil {
		t.Fatal(err)
	}
	obfu, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{src})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("output: plain=%d bytes obfu=%d bytes", len(plain.Bytes()), len(obfu.Bytes()))
	if len(obfu.Bytes()) != len(plain.Bytes())+1 {
		t.Fatalf("obfu should add exactly one options byte: plain=%d obfu=%d",
			len(plain.Bytes()), len(obfu.Bytes()))
	}
	if got := obfu.Bytes()[29]; got != 0 {
		t.Fatalf("crypt options byte should be 0 with no user hash, got 0x%02x", got)
	}

	// A crypt-capable source (0x01 supports) with a user hash: the hash is appended
	// and bit 0x80 joins the crypt bit, giving 0x81.
	withHash, err := BuildFoundSourcesObfuPacket(fileHash, []storage.Source{{
		ID: src.ID, Port: src.Port, CryptOptions: 0x01,
		UserHash: []byte("fedcba9876543210"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: obfu with crypt+user hash=%d bytes", len(withHash.Bytes()))
	if len(withHash.Bytes()) != len(obfu.Bytes())+16 {
		t.Fatalf("user hash should add 16 bytes: without=%d with=%d",
			len(obfu.Bytes()), len(withHash.Bytes()))
	}
	if got := withHash.Bytes()[29]; got != 0x81 {
		t.Fatalf("crypt options byte should be 0x81 (supports|hash), got 0x%02x", got)
	}
}
