package ed2k

import (
	"encoding/binary"
	"fmt"
	"strings"

	"enode/logging"

	"github.com/jedib0t/go-pretty/v6/table"
)

func LogTCPPacket(dir string, remote string, protocol uint8, opcode uint8, payload []byte) {
	size := uint32(len(payload) + 1)
	logging.DebugTablef(formatLogLine("tcp", dir, remote, protocolName(protocol), opcodeName(opcode, dir),
		fmt.Sprintf("%d", size), fmt.Sprintf("%d", len(payload))))
}

func LogTCPRaw(dir string, remote string, raw []byte) {
	proto, size, opcode, payload, ok := parseTCPRaw(raw)
	if !ok {
		logging.DebugTablef(formatLogLine("tcp", dir, remote, "-", "-", "-", "-"))
		return
	}
	logging.DebugTablef(formatLogLine("tcp", dir, remote, protocolName(proto), opcodeName(opcode, dir),
		fmt.Sprintf("%d", size), fmt.Sprintf("%d", len(payload))))
}

func LogUDPRaw(dir string, remote string, raw []byte) {
	proto, opcode, payload, ok := parseUDPRaw(raw)
	if !ok {
		logging.DebugTablef(formatLogLine("udp", dir, remote, "-", "-", "-", "-"))
		return
	}
	logging.DebugTablef(formatLogLine("udp", dir, remote, protocolName(proto), opcodeName(opcode, dir),
		"-", fmt.Sprintf("%d", len(payload))))
}

func parseTCPRaw(raw []byte) (uint8, uint32, uint8, []byte, bool) {
	if len(raw) < 6 {
		return 0, 0, 0, nil, false
	}
	proto := raw[0]
	size := binary.LittleEndian.Uint32(raw[1:5])
	if size == 0 {
		return proto, size, 0, nil, false
	}
	if int(5+size) > len(raw) {
		return proto, size, 0, nil, false
	}
	opcode := raw[5]
	payload := raw[6 : 5+size]
	return proto, size, opcode, payload, true
}

func parseUDPRaw(raw []byte) (uint8, uint8, []byte, bool) {
	if len(raw) < 2 {
		return 0, 0, nil, false
	}
	return raw[0], raw[1], raw[2:], true
}

func protocolName(p uint8) string {
	switch p {
	case PrED2K:
		return "PR_ED2K(0xe3)"
	case PrEMule:
		return "PR_EMULE(0xc5)"
	case PrZlib:
		return "PR_ZLIB(0xd4)"
	case PrNat:
		return "PR_NAT(0xf1)"
	default:
		return fmt.Sprintf("0x%02x", p)
	}
}

func opcodeName(op uint8, dir string) string {
	flow := directionLabel(dir)
	switch op {
	case OpLoginRequest:
		if flow == "C->S" {
			return "OP_LOGINREQUEST(0x01) C->S login/session registration"
		}
		return "OP_HELLO(0x01) S->C handshake check client path"
	case OpHelloAnswer:
		return "OP_HELLOANSWER(0x4c) " + flow
	case OpServerMessage:
		return "OP_SERVERMESSAGE(0x38) " + flow
	case OpServerStatus:
		return "OP_SERVERSTATUS(0x34) " + flow
	case OpIDChange:
		return "OP_IDCHANGE(0x40) " + flow
	case OpGetServerList:
		return "OP_GETSERVERLIST(0x14) " + flow
	case OpOfferFiles:
		return "OP_OFFERFILES(0x15) " + flow
	case OpServerList:
		return "OP_SERVERLIST(0x32) " + flow
	case OpServerIdent:
		return "OP_SERVERIDENT(0x41) " + flow
	case OpGetSources:
		return "OP_GETSOURCES(0x19) " + flow
	case OpFoundSources:
		return "OP_FOUNDSOURCES(0x42) " + flow
	case OpSearchRequest:
		return "OP_SEARCHREQUEST(0x16) " + flow
	case OpSearchResult:
		return "OP_SEARCHRESULT(0x33) " + flow
	case OpCallbackRequest:
		return "OP_CALLBACKREQUEST(0x1c) " + flow
	case OpCallbackReqd:
		return "OP_CALLBACKREQD(0x35) " + flow
	case OpCallbackFailed:
		return "OP_CALLBACKFAILED(0x36) " + flow
	case OpGetSourcesObfu:
		return "OP_GETSOURCES_OBFU(0x23) " + flow
	case OpFoundSourcesObfu:
		return "OP_FOUNDSOURCES_OBFU(0x44) " + flow
	case OpGlobSearchReq3:
		return "OP_GLOBSEARCHREQ3(0x90) " + flow
	case OpGlobSearchReq2:
		return "OP_GLOBSEARCHREQ2(0x92) " + flow
	case OpGlobGetSources2:
		return "OP_GLOBGETSOURCES2(0x94) " + flow
	case OpGlobServStatReq:
		return "OP_GLOBSERVSTATREQ(0x96) " + flow
	case OpGlobServStatRes:
		return "OP_GLOBSERVSTATRES(0x97) " + flow
	case OpGlobSearchReq:
		return "OP_GLOBSEARCHREQ(0x98) " + flow
	case OpGlobSearchRes:
		return "OP_GLOBSEARCHRES(0x99) " + flow
	case OpGlobGetSources:
		return "OP_GLOBGETSOURCES(0x9a) " + flow
	case OpGlobFoundSources:
		return "OP_GLOBFOUNDSOURCES(0x9b) " + flow
	case OpServerDescReq:
		return "OP_SERVERDESCREQ(0xa2) " + flow
	case OpServerDescRes:
		return "OP_SERVERDESCRES(0xa3) " + flow
	case OpNatSync:
		return "OP_NATSYNC(0xe1) " + flow
	case OpNatPing:
		return "OP_NATPING(0xe2) " + flow
	case OpNatRegister:
		return "OP_NATREGISTER(0xe4) " + flow
	case OpNatFailed:
		return "OP_NATFAILED(0xe5) " + flow
	case OpNatReping:
		return "OP_NATREPING(0xe8) " + flow
	case OpNatSync2:
		return "OP_NATSYNC2(0xe9) " + flow
	case OpNatData:
		return "OP_NATDATA(0xea) " + flow
	case OpNatAck:
		return "OP_NATACK(0xeb) " + flow
	case OpNatRst:
		return "OP_NATRST(0xef) " + flow
	default:
		return fmt.Sprintf("0x%02x %s", op, flow)
	}
}

func directionLabel(dir string) string {
	switch dir {
	case "recv", "recv-decompressed":
		return "C->S"
	case "send":
		return "S->C"
	default:
		return "?"
	}
}

func formatLogLine(proto, dir, remote, protocol, opcode, size, payloadLen string) string {
	var b strings.Builder
	tw := table.NewWriter()
	tw.SetOutputMirror(&b)
	tw.SetStyle(table.StyleLight)
	tw.AppendHeader(table.Row{"Proto", "Dir", "Flow", "Remote", "Protocol", "Opcode", "Size", "PayloadLen"})
	tw.AppendRow(table.Row{proto, dir, directionLabel(dir), remote, protocol, opcode, size, payloadLen})
	tw.Render()
	return strings.TrimRight(b.String(), "\n")
}
