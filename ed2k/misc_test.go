package ed2k

import "testing"

func TestExtAndType(t *testing.T) {
	if Ext("Movie.MKV") != "mkv" {
		t.Fatalf("ext mismatch")
	}
	if GetFileType("Movie.MKV") != "Video" {
		t.Fatalf("type mismatch")
	}
	if GetFileType("song.mp3") != "Audio" {
		t.Fatalf("type mismatch")
	}
	if GetFileType("a.unknown") != "" {
		t.Fatalf("unexpected type")
	}
}

func TestHex(t *testing.T) {
	if Hex(10, 4) != "000a" {
		t.Fatalf("hex mismatch: %s", Hex(10, 4))
	}
}

func TestIPv4ToInt32LE(t *testing.T) {
	v, err := IPv4ToInt32LE("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if v != 0x04030201 {
		t.Fatalf("value mismatch: 0x%x", v)
	}
}

func TestIsProtocolAndBox(t *testing.T) {
	if !IsProtocol(PrED2K) || IsProtocol(0xff) {
		t.Fatalf("protocol mismatch")
	}
	if Box("x") != "+---+\n| x |\n+---+" {
		t.Fatalf("box mismatch: %q", Box("x"))
	}
}
