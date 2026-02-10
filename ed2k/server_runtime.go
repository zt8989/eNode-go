package ed2k

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"enode/logging"
	"enode/storage"
)

type TCPRuntimeConfig struct {
	Name                 string
	Description          string
	Address              string
	Port                 uint16
	Flags                uint32
	Hash                 []byte
	MessageLogin         string
	MessageLowID         string
	ConnectionTimeout    time.Duration
	DisconnectTimeout    time.Duration
	ServerStatusInterval time.Duration
	AllowLowIDs          bool
	SupportCrypt         bool
}

type UDPRuntimeConfig struct {
	Name           string
	Description    string
	DynIP          string
	UDPFlags       uint32
	UDPPortObf     uint16
	TCPPortObf     uint16
	UDPServerKey   uint32
	MaxConnections uint32
}

type ServerRuntime struct {
	TCP     TCPRuntimeConfig
	UDP     UDPRuntimeConfig
	Storage storage.Engine
	LowIDs  *LowIDClients

	sessionsMu sync.Mutex
	sessions   map[string]*tcpClient
}

func NewServerRuntime(tcp TCPRuntimeConfig, udp UDPRuntimeConfig, store storage.Engine) *ServerRuntime {
	if tcp.ServerStatusInterval <= 0 {
		tcp.ServerStatusInterval = defaultServerStatusInterval
	}
	return &ServerRuntime{
		TCP:      tcp,
		UDP:      udp,
		Storage:  store,
		LowIDs:   NewLowIDClients(tcp.AllowLowIDs),
		sessions: map[string]*tcpClient{},
	}
}

func (s *ServerRuntime) TCPHandler(enableCrypt bool) func(net.Conn) {
	return func(conn net.Conn) {
		client := newTCPClient(s, conn, enableCrypt)
		client.run()
	}
}

func (s *ServerRuntime) UDPHandler(enableCrypt bool) func([]byte, *net.UDPAddr, *net.UDPConn) {
	crypt := NewUDPCrypt(enableCrypt, s.UDP.UDPServerKey)
	module := "udp"
	if enableCrypt {
		module = "udp-obfs"
	}
	return func(data []byte, remote *net.UDPAddr, conn *net.UDPConn) {
		if len(data) == 0 {
			return
		}
		if crypt != nil && crypt.Status == CsEncrypting {
			data = crypt.Decrypt(data)
		}
		LogUDPRaw(module, "recv", remote.String(), data)
		b := NewBufferFromBytes(data)
		protocol, err := b.GetUInt8()
		if err != nil {
			return
		}
		code, err := b.GetUInt8()
		if err != nil {
			return
		}
		if protocol != PrED2K {
			logging.Debugf("udp unsupported protocol remote=%s proto=0x%x", remote, protocol)
			return
		}
		switch code {
		case OpGlobGetSources:
			s.udpGlobGetSources(b, remote, conn, crypt, module)
		case OpGlobGetSources2:
			s.udpGlobGetSources2(b, remote, conn, crypt, module)
		case OpGlobServStatReq:
			s.udpGlobServStatReq(b, remote, conn, crypt, module)
		case OpServerDescReq:
			if len(data) < 6 {
				s.udpServDescResOld(remote, conn, crypt, module)
			} else {
				s.udpServDescRes(b, remote, conn, crypt, module)
			}
		case OpGlobSearchReq:
			s.udpGlobSearchReq(b, remote, conn, crypt, module)
		case OpGlobSearchReq3:
			s.udpGlobSearchReq3(b, remote, conn, crypt, module)
		default:
			logging.Debugf("udp unknown opcode remote=%s opcode=0x%x", remote, code)
		}
	}
}

type tcpClient struct {
	server      *ServerRuntime
	conn        net.Conn
	packet      *Packet
	crypt       *TCPCrypt
	module      string
	writeMu     sync.Mutex
	closeMu     sync.Mutex
	info        storage.ClientInfo
	logged      bool
	hasLowID    bool
	remoteHost  string
	sessionKey  string
	statusStop  chan struct{}
	closeReason string
}

func newTCPClient(server *ServerRuntime, conn net.Conn, enableCrypt bool) *tcpClient {
	host := ""
	if addr := conn.RemoteAddr(); addr != nil {
		host = splitHost(addr.String())
	}
	ipv4, err := IPv4ToInt32LE(host)
	if err != nil {
		ipv4 = 0
	}
	packet := NewPacket()
	var crypt *TCPCrypt
	if enableCrypt {
		crypt = NewTCPCrypt(packet, true)
	}
	enableTCPKeepAlive(conn, defaultTCPKeepAlivePeriod)
	return &tcpClient{
		server:     server,
		conn:       conn,
		packet:     packet,
		crypt:      crypt,
		module:     tcpModule(enableCrypt),
		hasLowID:   true,
		remoteHost: host,
		info: storage.ClientInfo{
			IPv4:  ipv4,
			ID:    0,
			Port:  0,
			LowID: true,
		},
	}
}

const defaultTCPKeepAlivePeriod = 2 * time.Minute
const defaultServerStatusInterval = 5 * time.Minute

func enableTCPKeepAlive(conn net.Conn, period time.Duration) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcp.SetKeepAlive(true); err != nil {
		return
	}
	if period > 0 {
		_ = tcp.SetKeepAlivePeriod(period)
	}
}

func (c *tcpClient) run() {
	c.setCloseReason("read-loop-ended")
	defer func() {
		if c.statusStop != nil {
			close(c.statusStop)
		}
		if c.sessionKey != "" {
			c.server.unregisterSession(c.sessionKey, c)
		}
		if c.hasLowID {
			c.server.LowIDs.Remove(c.info.ID)
		}
		if c.logged {
			c.server.Storage.Disconnect(c.info)
		}
		_ = c.conn.Close()
		logging.Infof("tcp session closed remote=%s id=%d lowID=%t storeID=%d reason=%s",
			c.remoteHost, c.info.ID, c.info.LowID, c.info.StoreID, c.getCloseReason())
	}()

	buf := make([]byte, 4096)
	for {
		if c.server.TCP.DisconnectTimeout > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(c.server.TCP.DisconnectTimeout))
		}
		n, err := c.conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.setCloseReason("peer-closed")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				c.setCloseReason(fmt.Sprintf("read-timeout(%s)", c.server.TCP.DisconnectTimeout))
			} else {
				c.setCloseReason(fmt.Sprintf("read-error: %v", err))
			}
			return
		}
		if n == 0 {
			c.setCloseReason("read-zero")
			return
		}
		c.handleBytes(buf[:n])
	}
}

func (c *tcpClient) handleBytes(data []byte) {
	if c.crypt != nil {
		switch c.crypt.State {
		case CsUnknown, CsNegotiating:
			state := c.crypt.State
			rest, err := c.crypt.ProcessData(NewBufferFromBytes(data))
			if err != nil {
				logging.Warnf("tcp crypt error remote=%s err=%v", c.remoteHost, err)
				return
			}
			if state == CsUnknown {
				if len(rest) > 0 {
					_ = c.writeRaw(rest)
				}
				return
			}
			if len(rest) == 0 {
				return
			}
			data = rest
		case CsEncrypting:
			data = c.crypt.Decrypt(data)
		}
	}
	c.processPacketData(data)
}

func (c *tcpClient) processPacketData(data []byte) {
	buf := NewBufferFromBytes(data)
	switch c.packet.Status {
	case PsNew:
		if err := c.packet.Init(buf, nil); err != nil {
			return
		}
	case PsWaitingData:
		c.packet.Append(buf.Get())
	default:
		return
	}

	if c.packet.Status != PsReady {
		return
	}

	c.handlePacket(c.packet)
	c.packet.Status = PsNew
	if c.packet.HasExcess && len(c.packet.Excess) > 0 {
		excess := append([]byte(nil), c.packet.Excess...)
		c.packet.HasExcess = false
		c.packet.Excess = nil
		c.processPacketData(excess)
	}
}

func (c *tcpClient) handlePacket(packet *Packet) {
	switch packet.Protocol {
	case PrED2K:
		LogTCPPacket(c.module, "recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
		c.handleED2K(packet.Code, packet.Data)
	case PrZlib:
		LogTCPPacket(c.module, "recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
		payload, err := InflateZlibPayload(packet.Data.Bytes())
		if err != nil {
			logging.Warnf("tcp zlib inflate failed remote=%s err=%v", c.remoteHost, err)
			return
		}
		LogTCPPacket(c.module, "recv-decompressed", c.remoteHost, PrED2K, packet.Code, payload)
		c.handleED2K(packet.Code, NewBufferFromBytes(payload))
	default:
		LogTCPPacket(c.module, "recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
		logging.Debugf("tcp unsupported protocol remote=%s proto=0x%x", c.remoteHost, packet.Protocol)
	}
}

func (c *tcpClient) handleED2K(opcode uint8, data *Buffer) {
	data.Pos(0)
	switch opcode {
	case OpLoginRequest:
		c.handleLoginRequest(data)
	case OpOfferFiles:
		c.handleOfferFiles(data)
	case OpGetServerList:
		c.handleGetServerList()
	case OpGetSources:
		c.handleGetSources(data, false)
	case OpGetSourcesObfu:
		c.handleGetSources(data, true)
	case OpSearchRequest:
		c.handleSearchRequest(data)
	case OpCallbackRequest:
		c.handleCallbackRequest(data)
	default:
		logging.Debugf("tcp unhandled opcode remote=%s opcode=0x%x", c.remoteHost, opcode)
	}
}

func (c *tcpClient) handleLoginRequest(data *Buffer) {
	req, err := ParseLoginRequest(data)
	if err != nil {
		logging.Warnf("login request parse failed remote=%s err=%v", c.remoteHost, err)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_LOGINREQUEST hash=%x id=%d port=%d tags=%s",
		c.remoteHost, req.Hash, req.ID, req.Port, formatNamedTags(req.Tags, 32))
	sessionKey := loginSessionKey(req.Hash, req.ID)
	if sessionKey != "" {
		c.sessionKey = sessionKey
		c.server.replaceSession(sessionKey, c)
	}
	c.info.Hash = req.Hash
	c.info.ID = req.ID
	c.info.Port = req.Port

	firewalled := c.server.isFirewalled(c)
	logging.Debugf("login decision remote=%s requestedID=%d firewalled=%t", c.remoteHost, req.ID, firewalled)
	if firewalled {
		c.hasLowID = true
		c.info.LowID = true
		c.sendServerMessage(c.server.TCP.MessageLowID)
		id, ok := c.server.LowIDs.AddByEndpoint(c.info.IPv4, c.info.Port, c)
		if !ok {
			c.closeWithReason("lowid-pool-exhausted")
			return
		}
		c.info.ID = id
	} else {
		c.hasLowID = false
		c.info.LowID = false
		c.info.ID = c.info.IPv4
	}
	logging.Infof("login accepted remote=%s assignedID=%d lowID=%t port=%d", c.remoteHost, c.info.ID, c.info.LowID, c.info.Port)
	c.handShake()
}

func (s *ServerRuntime) replaceSession(key string, client *tcpClient) {
	if key == "" || client == nil {
		return
	}
	s.sessionsMu.Lock()
	old := s.sessions[key]
	s.sessions[key] = client
	s.sessionsMu.Unlock()
	if old != nil && old != client {
		logging.Infof("tcp replace-session key=%s old=%s new=%s", key, old.remoteHost, client.remoteHost)
		old.closeWithReason(fmt.Sprintf("replaced-by-new-session(key=%s,new=%s)", key, client.remoteHost))
	}
}

func (s *ServerRuntime) unregisterSession(key string, client *tcpClient) {
	if key == "" || client == nil {
		return
	}
	s.sessionsMu.Lock()
	if cur, ok := s.sessions[key]; ok && cur == client {
		delete(s.sessions, key)
	}
	s.sessionsMu.Unlock()
}

func loginSessionKey(hash []byte, id uint32) string {
	if len(hash) == 16 {
		return fmt.Sprintf("h:%x", hash)
	}
	if id != 0 {
		return fmt.Sprintf("i:%08x", id)
	}
	return ""
}

func (c *tcpClient) handShake() {
	storeID, err := c.server.Storage.Connect(c.info)
	if err != nil {
		logging.Warnf("storage connect failed remote=%s err=%v", c.remoteHost, err)
		c.closeWithReason(fmt.Sprintf("storage-connect-failed: %v", err))
		return
	}
	c.logged = true
	c.info.StoreID = storeID
	logging.Infof("login handshake complete remote=%s storeID=%d id=%d lowID=%t", c.remoteHost, c.info.StoreID, c.info.ID, c.info.LowID)

	c.sendServerMessage(c.server.TCP.MessageLogin)
	c.sendServerMessage(fmt.Sprintf("server version %s (%s)", ENodeVersionStr, ENodeName))
	c.sendServerStatus()
	c.startPeriodicServerStatus()
	c.sendIDChange(c.info.ID)
	c.sendServerIdent()
}

func (c *tcpClient) setCloseReason(reason string) {
	if reason == "" {
		return
	}
	c.closeMu.Lock()
	if c.closeReason == "" || c.closeReason == "read-loop-ended" {
		c.closeReason = reason
	}
	c.closeMu.Unlock()
}

func (c *tcpClient) getCloseReason() string {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closeReason == "" {
		return "unknown"
	}
	return c.closeReason
}

func (c *tcpClient) closeWithReason(reason string) {
	c.setCloseReason(reason)
	_ = c.conn.Close()
}

func (c *tcpClient) startPeriodicServerStatus() {
	if c.statusStop != nil {
		return
	}
	interval := c.server.TCP.ServerStatusInterval
	if interval <= 0 {
		return
	}
	c.statusStop = make(chan struct{})
	go func(stop <-chan struct{}) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if c.logged {
					c.sendServerStatus()
				}
			case <-stop:
				return
			}
		}
	}(c.statusStop)
}

func (c *tcpClient) handleOfferFiles(data *Buffer) {
	raw := append([]byte(nil), data.Bytes()...)
	records, err := data.GetFileList()
	if err != nil {
		previewLen := 96
		if len(raw) < previewLen {
			previewLen = len(raw)
		}
		previewHex := hex.EncodeToString(raw[:previewLen])
		logging.Warnf("offer files parse failed remote=%s payloadLen=%d previewHex=%s err=%v",
			c.remoteHost, len(raw), previewHex, err)
		return
	}
	const maxOfferFilesLog = 50
	logging.Debugf("offer files remote=%s count=%d payloadLen=%d", c.remoteHost, len(records), len(raw))
	for _, record := range records {
		file := fileFromRecord(record, c.info)
		c.server.Storage.AddFile(file, c.info)
	}
	limit := len(records)
	if limit > maxOfferFilesLog {
		limit = maxOfferFilesLog
	}
	for i := 0; i < limit; i++ {
		record := records[i]
		file := fileFromRecord(record, c.info)
		logging.Debugf("offer file remote=%s idx=%d hash=%x name=%q size=%d type=%q sourceID=%d sourcePort=%d",
			c.remoteHost, i, record.Hash, file.Name, file.Size, file.Type, c.info.ID, c.info.Port)
	}
	if len(records) > maxOfferFilesLog {
		logging.Debugf("offer files remote=%s truncated=%d", c.remoteHost, len(records)-maxOfferFilesLog)
	}
}

func (c *tcpClient) handleGetServerList() {
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_GETSERVERLIST payload=empty", c.remoteHost)
	c.sendServerList()
	c.sendServerIdent()
}

func (c *tcpClient) handleGetSources(data *Buffer, obfuscated bool) {
	hash := append([]byte(nil), data.Get(16)...)
	if len(hash) != 16 {
		logging.Warnf("get sources parse failed remote=%s opcode=%s err=invalid-hash-len", c.remoteHost, opNameGetSources(obfuscated))
		return
	}
	size, err := data.GetUInt32LE()
	if err != nil {
		logging.Warnf("get sources parse failed remote=%s opcode=%s err=%v", c.remoteHost, opNameGetSources(obfuscated), err)
		return
	}
	fileSize := uint64(size)
	if fileSize == 0 {
		v, err := data.GetUInt64LE()
		if err != nil {
			logging.Warnf("get sources parse failed remote=%s opcode=%s err=%v", c.remoteHost, opNameGetSources(obfuscated), err)
			return
		}
		fileSize = v
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=%s hash=%x fileSize=%d",
		c.remoteHost, opNameGetSources(obfuscated), hash, fileSize)
	sources := c.server.Storage.GetSources(hash, fileSize)
	c.debugPayloadf("tcp payload parsed remote=%s opcode=%s sourcesFound=%d", c.remoteHost, opNameGetSources(obfuscated), len(sources))
	if len(sources) == 0 {
		return
	}
	c.sendFoundSources(hash, sources, obfuscated)
}

func (c *tcpClient) handleSearchRequest(data *Buffer) {
	expr, err := ParseSearchExpr(data)
	if err != nil {
		logging.Warnf("search request parse failed remote=%s err=%v", c.remoteHost, err)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_SEARCHREQUEST expr=%s", c.remoteHost, formatSearchExpr(expr))
	files := c.server.Storage.FindBySearch(expr)
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_SEARCHREQUEST resultCount=%d", c.remoteHost, len(files))
	if len(files) == 0 {
		return
	}
	c.sendSearchResult(files)
}

func (c *tcpClient) handleCallbackRequest(data *Buffer) {
	lowID, err := data.GetUInt32LE()
	if err != nil {
		logging.Warnf("callback request parse failed remote=%s err=%v", c.remoteHost, err)
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d", c.remoteHost, lowID)
	v, ok := c.server.LowIDs.Get(lowID)
	if !ok {
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d result=not-found", c.remoteHost, lowID)
		c.sendCallbackFailed()
		return
	}
	target, ok := v.(*tcpClient)
	if !ok {
		c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d result=invalid-target-type", c.remoteHost, lowID)
		c.sendCallbackFailed()
		return
	}
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d targetIPv4=%d targetPort=%d",
		c.remoteHost, lowID, target.info.IPv4, target.info.Port)
	if err := target.sendCallbackRequested(c.info.IPv4, c.info.Port); err != nil {
		c.sendCallbackFailed()
	}
}

func (c *tcpClient) sendFoundSources(hash []byte, sources []storage.Source, obfuscated bool) {
	var (
		packet *Buffer
		err    error
	)
	if obfuscated {
		packet, err = BuildFoundSourcesObfuPacket(hash, sources)
	} else {
		packet, err = BuildFoundSourcesPacket(hash, sources)
	}
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendSearchResult(files []storage.File) {
	packet, err := BuildSearchResultPacket(files)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendServerList() {
	servers := c.server.Storage.ServersAll()
	packet, err := BuildServerListPacket(servers)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendServerStatus() {
	packet, err := BuildServerStatusPacket(c.server.Storage.ClientsCount(), c.server.Storage.FilesCount())
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendIDChange(id uint32) {
	packet, err := BuildIDChangePacket(id, c.server.TCP.Flags)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendCallbackFailed() {
	packet, err := BuildCallbackFailedPacket()
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendServerIdent() {
	packet, err := BuildServerIdentPacket(ServerConfig{
		Name:        c.server.TCP.Name,
		Description: c.server.TCP.Description,
		Address:     c.server.TCP.Address,
		Hash:        c.server.TCP.Hash,
		TCPPort:     c.server.TCP.Port,
		TCPFlags:    c.server.TCP.Flags,
	})
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendServerMessage(message string) {
	if message == "" {
		return
	}
	packet, err := BuildServerMessagePacket(message)
	if err != nil {
		return
	}
	_ = c.writePacket(packet)
}

func (c *tcpClient) sendCallbackRequested(ipv4 uint32, port uint16) error {
	packet, err := BuildCallbackRequestedPacket(ipv4, port)
	if err != nil {
		return err
	}
	return c.writePacket(packet)
}

func (c *tcpClient) writePacket(packet *Buffer) error {
	if packet == nil {
		return nil
	}
	return c.writeRaw(packet.Bytes())
}

func (c *tcpClient) writeRaw(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	LogTCPRaw(c.module, "send", c.remoteHost, data)
	c.logSendPayload(data)
	if c.crypt != nil && c.crypt.State == CsEncrypting {
		data = RC4Crypt(data, len(data), c.crypt.SendKey)
	}
	_, err := c.conn.Write(data)
	return err
}

func (c *tcpClient) debugPayloadf(format string, args ...any) {
	all := make([]any, 0, len(args)+1)
	all = append(all, c.module)
	all = append(all, args...)
	logging.Debugf("[module=%s] "+format, all...)
}

func (c *tcpClient) logSendPayload(raw []byte) {
	proto, _, opcode, payload, ok := parseTCPRaw(raw)
	if !ok {
		return
	}
	if proto == PrZlib {
		inflated, err := InflateZlibPayload(payload)
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send protocol=PR_ZLIB opcode=%s err=%v",
				c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send protocol=PR_ZLIB opcode=%s compressedPayloadLen=%d decompressedPayloadLen=%d",
			c.remoteHost, opcodeLabel(opcode), len(payload), len(inflated))
		c.logSendPayloadByOpcode(opcode, inflated)
		return
	}
	c.logSendPayloadByOpcode(opcode, payload)
}

func (c *tcpClient) logSendPayloadByOpcode(opcode uint8, payload []byte) {
	b := NewBufferFromBytes(payload)
	switch opcode {
	case OpServerMessage:
		msg, err := b.GetString()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s message=%q", c.remoteHost, opcodeLabel(opcode), msg)
	case OpServerStatus:
		users, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		files, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s users=%d files=%d", c.remoteHost, opcodeLabel(opcode), users, files)
	case OpIDChange:
		id, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		flags, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s id=%d flags=%d", c.remoteHost, opcodeLabel(opcode), id, flags)
	case OpServerList:
		count, err := b.GetUInt8()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		entries := make([]string, 0, count)
		limit := int(count)
		if limit > 20 {
			limit = 20
		}
		for i := 0; i < int(count); i++ {
			ipv4, err := b.GetUInt32LE()
			if err != nil {
				logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
				return
			}
			port, err := b.GetUInt16LE()
			if err != nil {
				logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
				return
			}
			if i < limit {
				entries = append(entries, fmt.Sprintf("{ip=%d,port=%d}", ipv4, port))
			}
		}
		if int(count) > limit {
			entries = append(entries, fmt.Sprintf("...+%d", int(count)-limit))
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s serverCount=%d servers=[%s]",
			c.remoteHost, opcodeLabel(opcode), count, strings.Join(entries, ", "))
	case OpServerIdent:
		hash := b.Get(16)
		if len(hash) != 16 {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=invalid-hash-len", c.remoteHost, opcodeLabel(opcode))
			return
		}
		ipv4, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		tags, err := b.GetTags()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s hash=%x ip=%d port=%d tags=%s",
			c.remoteHost, opcodeLabel(opcode), hash, ipv4, port, formatNamedTags(tags, 24))
	case OpFoundSources:
		hash, count, entries, err := parseFoundSourcesPayload(payload, false, 20)
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s fileHash=%x sourceCount=%d payloadLen=%d sources=%s",
			c.remoteHost, opcodeLabel(opcode), hash, count, len(payload), entries)
	case OpFoundSourcesObfu:
		hash, count, entries, err := parseFoundSourcesPayload(payload, true, 20)
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s fileHash=%x sourceCount=%d payloadLen=%d sources=%s",
			c.remoteHost, opcodeLabel(opcode), hash, count, len(payload), entries)
	case OpSearchResult:
		files, err := b.GetFileList()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s resultCount=%d files=%s",
			c.remoteHost, opcodeLabel(opcode), len(files), formatFileRecordsForLog(files, 5))
	case OpCallbackReqd:
		ipv4, err := b.GetUInt32LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			logging.Warnf("tcp payload parse failed remote=%s dir=send opcode=%s err=%v", c.remoteHost, opcodeLabel(opcode), err)
			return
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s targetIP=%d targetPort=%d",
			c.remoteHost, opcodeLabel(opcode), ipv4, port)
	case OpCallbackFailed:
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s payload=empty", c.remoteHost, opcodeLabel(opcode))
	default:
		previewLen := len(payload)
		if previewLen > 128 {
			previewLen = 128
		}
		c.debugPayloadf("tcp payload parsed remote=%s dir=send opcode=%s payloadLen=%d previewHex=%s",
			c.remoteHost, opcodeLabel(opcode), len(payload), hex.EncodeToString(payload[:previewLen]))
	}
}

func parseFoundSourcesPayload(payload []byte, withObfu bool, limit int) ([]byte, int, string, error) {
	b := NewBufferFromBytes(payload)
	hash := b.Get(16)
	if len(hash) != 16 {
		return nil, 0, "", fmt.Errorf("invalid-hash-len")
	}
	count, err := b.GetUInt8()
	if err != nil {
		return nil, 0, "", err
	}
	if limit <= 0 {
		limit = 20
	}
	n := int(count)
	if n > limit {
		n = limit
	}
	parts := make([]string, 0, n+1)
	for i := 0; i < int(count); i++ {
		id, err := b.GetUInt32LE()
		if err != nil {
			return nil, 0, "", err
		}
		port, err := b.GetUInt16LE()
		if err != nil {
			return nil, 0, "", err
		}
		if withObfu {
			obf, err := b.GetUInt8()
			if err != nil {
				return nil, 0, "", err
			}
			if (obf & 0x80) != 0 {
				userHash := b.Get(16)
				if len(userHash) != 16 {
					return nil, 0, "", ErrOutOfBounds
				}
				if i < n {
					parts = append(parts, fmt.Sprintf("{id=%d,port=%d,obfSettings=0x%02x,userHash=%x}", id, port, obf, userHash))
				}
				continue
			}
			if i < n {
				parts = append(parts, fmt.Sprintf("{id=%d,port=%d,obfSettings=0x%02x}", id, port, obf))
			}
			continue
		}
		if i < n {
			parts = append(parts, fmt.Sprintf("{id=%d,port=%d}", id, port))
		}
	}
	if int(count) > n {
		parts = append(parts, fmt.Sprintf("...+%d", int(count)-n))
	}
	return hash, int(count), "[" + strings.Join(parts, ", ") + "]", nil
}

func formatFileRecordsForLog(files []FileRecord, limit int) string {
	if len(files) == 0 {
		return "[]"
	}
	if limit <= 0 {
		limit = 5
	}
	n := len(files)
	if n > limit {
		n = limit
	}
	parts := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		name, _ := files[i].Tags["name"].(string)
		parts = append(parts, fmt.Sprintf("{hash=%x,id=%d,port=%d,size=%d,name=%q}", files[i].Hash, files[i].ID, files[i].Port, files[i].Size, name))
	}
	if len(files) > n {
		parts = append(parts, fmt.Sprintf("...+%d", len(files)-n))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func opcodeLabel(opcode uint8) string {
	switch opcode {
	case OpServerMessage:
		return "OP_SERVERMESSAGE"
	case OpServerStatus:
		return "OP_SERVERSTATUS"
	case OpIDChange:
		return "OP_IDCHANGE"
	case OpServerList:
		return "OP_SERVERLIST"
	case OpServerIdent:
		return "OP_SERVERIDENT"
	case OpFoundSources:
		return "OP_FOUNDSOURCES"
	case OpFoundSourcesObfu:
		return "OP_FOUNDSOURCES_OBFU"
	case OpSearchResult:
		return "OP_SEARCHRESULT"
	case OpCallbackReqd:
		return "OP_CALLBACKREQD"
	case OpCallbackFailed:
		return "OP_CALLBACKFAILED"
	default:
		return fmt.Sprintf("0x%02x", opcode)
	}
}

func (s *ServerRuntime) isFirewalled(client *tcpClient) bool {
	if client == nil {
		return true
	}
	if s.TCP.SupportCrypt {
		ok, err := s.probeClient(client, true)
		if err == nil && ok {
			return false
		}
	}
	ok, err := s.probeClient(client, false)
	return err != nil || !ok
}

func (s *ServerRuntime) probeClient(client *tcpClient, enableCrypt bool) (bool, error) {
	if client.info.Port == 0 {
		return false, fmt.Errorf("client port is 0")
	}
	addr := net.JoinHostPort(client.remoteHost, fmt.Sprintf("%d", client.info.Port))
	dialer := net.Dialer{Timeout: s.TCP.ConnectionTimeout}
	if s.TCP.Address != "" && s.TCP.Address != "0.0.0.0" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(s.TCP.Address)}
	}
	conn, err := dialer.Dial("tcp4", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	cli := NewClient(ClientConfig{
		EnableCrypt:       enableCrypt,
		Address:           s.TCP.Address,
		TCPPort:           s.TCP.Port,
		ConnectionTimeout: int(s.TCP.ConnectionTimeout / time.Millisecond),
		Hash:              s.TCP.Hash,
	})
	cli.Hash = client.info.Hash

	if enableCrypt {
		pad, err := RandBuf(Rand(0xff))
		if err != nil {
			return false, err
		}
		handshake, err := cli.BuildHandshake(RandProtocol(), uint32(Rand(0xffffffff)), pad)
		if err != nil {
			return false, err
		}
		if err := writeWithDeadline(conn, handshake, s.TCP.ConnectionTimeout); err != nil {
			return false, err
		}
		if _, err := readHandshake(cli, conn, s.TCP.ConnectionTimeout); err != nil {
			return false, err
		}
	}

	hello, err := cli.BuildHelloPacket()
	if err != nil {
		return false, err
	}
	helloBytes := hello.Bytes()
	if enableCrypt && cli.CryptStatus == CsEncrypting {
		helloBytes = RC4Crypt(helloBytes, len(helloBytes), cli.SendKey)
	}
	if err := writeWithDeadline(conn, helloBytes, s.TCP.ConnectionTimeout); err != nil {
		return false, err
	}
	return readHelloAnswer(cli, conn, s.TCP.ConnectionTimeout)
}

func readHandshake(cli *Client, conn net.Conn, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	data, done, err := cli.Decrypt(buf[:n])
	if err != nil {
		return nil, err
	}
	if !done {
		return nil, errors.New("handshake incomplete")
	}
	return data, nil
}

func readHelloAnswer(cli *Client, conn net.Conn, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	var buffer []byte
	buf := make([]byte, 4096)

	for {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			return false, err
		}
		data := buf[:n]
		if cli.CryptStatus == CsEncrypting {
			data, _, err = cli.Decrypt(data)
			if err != nil {
				return false, err
			}
		}
		buffer = append(buffer, data...)

		for {
			if len(buffer) < 6 {
				break
			}
			if buffer[0] != PrED2K {
				return false, fmt.Errorf("bad protocol 0x%x", buffer[0])
			}
			size := int(binary.LittleEndian.Uint32(buffer[1:5]))
			if size <= 0 || len(buffer) < 5+size {
				break
			}
			payload := buffer[5 : 5+size]
			opcode := payload[0]
			if opcode == OpHelloAnswer {
				p := NewBufferFromBytes(payload[1:])
				_, _ = ReadOpHelloAnswer(p)
				return true, nil
			}
			buffer = buffer[5+size:]
		}
	}
}

func writeWithDeadline(conn net.Conn, data []byte, timeout time.Duration) error {
	if timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	}
	_, err := conn.Write(data)
	return err
}

func (s *ServerRuntime) udpGlobGetSources(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	for b.Pos()+16 <= len(b.Bytes()) {
		hash := append([]byte(nil), b.Get(16)...)
		if len(hash) != 16 {
			return
		}
		sources := s.Storage.GetSourcesByHash(hash)
		if len(sources) == 0 {
			continue
		}
		packet, err := BuildGlobFoundSourcesPacket(hash, sources)
		if err != nil {
			continue
		}
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

func (s *ServerRuntime) udpGlobGetSources2(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	for b.Pos()+20 <= len(b.Bytes()) {
		hash := append([]byte(nil), b.Get(16)...)
		if len(hash) != 16 {
			return
		}
		size, err := b.GetUInt32LE()
		if err != nil {
			return
		}
		fileSize := uint64(size)
		if fileSize == 0 {
			v, err := b.GetUInt64LE()
			if err != nil {
				return
			}
			fileSize = v
		}
		sources := s.Storage.GetSources(hash, fileSize)
		if len(sources) == 0 {
			continue
		}
		packet, err := BuildGlobFoundSourcesPacket(hash, sources)
		if err != nil {
			continue
		}
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

func (s *ServerRuntime) udpGlobServStatReq(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	challenge, err := b.GetUInt32LE()
	if err != nil {
		return
	}
	packet, err := BuildGlobServStatResPacket(challenge, UDPConfig{
		Name:           s.UDP.Name,
		Description:    s.UDP.Description,
		DynIP:          s.UDP.DynIP,
		UDPFlags:       s.UDP.UDPFlags,
		UDPPortObf:     s.UDP.UDPPortObf,
		TCPPortObf:     s.UDP.TCPPortObf,
		UDPServerKey:   s.UDP.UDPServerKey,
		MaxConnections: s.UDP.MaxConnections,
	}, s.Storage.ClientsCount(), s.Storage.FilesCount(), int(s.LowIDs.Count()))
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
}

func (s *ServerRuntime) udpServDescResOld(remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	packet, err := BuildServerDescResOldPacket(s.UDP.Name, s.UDP.Description)
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
}

func (s *ServerRuntime) udpServDescRes(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	challenge, err := b.GetUInt32LE()
	if err != nil {
		return
	}
	packet, err := BuildServerDescResPacket(challenge, UDPConfig{
		Name:        s.UDP.Name,
		Description: s.UDP.Description,
		DynIP:       s.UDP.DynIP,
	})
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
}

func (s *ServerRuntime) udpGlobSearchReq(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	expr, err := ParseSearchExpr(b)
	if err != nil {
		return
	}
	files := s.Storage.FindBySearch(expr)
	if len(files) == 0 {
		return
	}
	packets, err := BuildGlobSearchResPackets(files)
	if err != nil {
		return
	}
	for _, packet := range packets {
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

func (s *ServerRuntime) udpGlobSearchReq3(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt, module string) {
	_, _ = b.GetTags()
	expr, err := ParseSearchExpr(b)
	if err != nil {
		return
	}
	files := s.Storage.FindBySearch(expr)
	if len(files) == 0 {
		return
	}
	packets, err := BuildGlobSearchResPackets(files)
	if err != nil {
		return
	}
	for _, packet := range packets {
		_ = udpSend(conn, remote, packet.Bytes(), crypt, module)
	}
}

func udpSend(conn *net.UDPConn, remote *net.UDPAddr, data []byte, crypt *UDPCrypt, module string) error {
	LogUDPRaw(module, "send", remote.String(), data)
	if crypt != nil && crypt.Status == CsEncrypting {
		data = crypt.Encrypt(data)
	}
	_, err := conn.WriteToUDP(data, remote)
	return err
}

func fileFromRecord(record FileRecord, info storage.ClientInfo) storage.File {
	file := storage.File{
		Hash:       record.Hash,
		Size:       record.Size,
		SourceID:   info.ID,
		SourcePort: info.Port,
	}
	if v, ok := record.Tags["name"].(string); ok {
		file.Name = v
	}
	if v, ok := record.Tags["type"].(string); ok {
		file.Type = v
	}
	if v, ok := record.Tags["sources"].(uint32); ok {
		file.Sources = v
	}
	if v, ok := record.Tags["completesources"].(uint32); ok {
		file.Completed = v
	} else if record.Complete {
		file.Completed = 1
	}
	if v, ok := record.Tags["title"].(string); ok {
		file.Title = v
	}
	if v, ok := record.Tags["artist"].(string); ok {
		file.Artist = v
	}
	if v, ok := record.Tags["album"].(string); ok {
		file.Album = v
	}
	if v, ok := record.Tags["length"].(uint32); ok {
		file.Runtime = v
	}
	if v, ok := record.Tags["bitrate"].(uint32); ok {
		file.Bitrate = v
	}
	if v, ok := record.Tags["codec"].(string); ok {
		file.Codec = v
	}
	if file.Type == "" && file.Name != "" {
		file.Type = GetFileType(file.Name)
	}
	return file
}

func splitHost(addr string) string {
	if strings.Contains(addr, ":") {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			return host
		}
	}
	return addr
}

func tcpModule(enableCrypt bool) string {
	if enableCrypt {
		return "tcp-obfs"
	}
	return "tcp"
}

func opNameGetSources(obfuscated bool) string {
	if obfuscated {
		return "OP_GETSOURCES_OBFU"
	}
	return "OP_GETSOURCES"
}

func formatNamedTags(tags []NamedTag, limit int) string {
	if len(tags) == 0 {
		return "[]"
	}
	if limit <= 0 {
		limit = 32
	}
	n := len(tags)
	if n > limit {
		n = limit
	}
	parts := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf("%s=%v", tags[i].Name, tags[i].Value))
	}
	if len(tags) > n {
		parts = append(parts, fmt.Sprintf("...+%d", len(tags)-n))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatSearchExpr(expr *storage.SearchExpr) string {
	if expr == nil {
		return "<nil>"
	}
	switch expr.Kind {
	case storage.SearchText:
		return fmt.Sprintf("TEXT(%q)", expr.Text)
	case storage.SearchString:
		return fmt.Sprintf("STRING(tag=0x%x,val=%q)", expr.TagType, expr.ValueString)
	case storage.SearchUInt32:
		return fmt.Sprintf("U32(tag=0x%x,val=%d)", expr.TagType, expr.ValueUint)
	case storage.SearchUInt64:
		return fmt.Sprintf("U64(tag=0x%x,val=%d)", expr.TagType, expr.ValueUint)
	case storage.SearchAnd:
		return fmt.Sprintf("AND(%s,%s)", formatSearchExpr(expr.Left), formatSearchExpr(expr.Right))
	case storage.SearchOr:
		return fmt.Sprintf("OR(%s,%s)", formatSearchExpr(expr.Left), formatSearchExpr(expr.Right))
	case storage.SearchAndNot:
		return fmt.Sprintf("ANDNOT(%s,%s)", formatSearchExpr(expr.Left), formatSearchExpr(expr.Right))
	default:
		return fmt.Sprintf("UNKNOWN(kind=%d)", expr.Kind)
	}
}
