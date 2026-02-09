package ed2k

import "testing"

func TestBuildTCPFlags(t *testing.T) {
	flags := BuildTCPFlags(TCPServerConfig{
		AuxiliarPort: true, RequireCrypt: true, RequestCrypt: true, SupportCrypt: true, IPInLogin: true,
	})
	expected := FlagZlib + FlagNewTags + FlagUnicode + FlagLargeFiles + FlagAuxPort + FlagRequireCrypt + FlagRequestCrypt + FlagSupportCrypt + FlagIPInLogin
	if flags != expected {
		t.Fatalf("flags mismatch: got 0x%x expected 0x%x", flags, expected)
	}
}

func TestBuildUDPFlags(t *testing.T) {
	flags := BuildUDPFlags(UDPServerConfig{
		GetSources: true, GetFiles: true, SupportCrypt: true,
	})
	expected := FlagNewTags + FlagUnicode + FlagLargeFiles + FlagUdpExtSources + FlagUdpExtSrc2 + FlagUdpExtFiles + FlagUdpObfusc + FlagTcpObfusc
	if flags != expected {
		t.Fatalf("flags mismatch: got 0x%x expected 0x%x", flags, expected)
	}
}
