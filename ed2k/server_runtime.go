package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"enode/logging"
	"enode/storage"
)

type TCPRuntimeConfig struct {
	Name              string
	Description       string
	Address           string
	Port              uint16
	Flags             uint32
	Hash              []byte
	MessageLogin      string
	MessageLowID      string
	ConnectionTimeout time.Duration
	DisconnectTimeout time.Duration
	AllowLowIDs       bool
	SupportCrypt      bool
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
}

func NewServerRuntime(tcp TCPRuntimeConfig, udp UDPRuntimeConfig, store storage.Engine) *ServerRuntime {
	return &ServerRuntime{
		TCP:     tcp,
		UDP:     udp,
		Storage: store,
		LowIDs:  NewLowIDClients(tcp.AllowLowIDs),
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
	return func(data []byte, remote *net.UDPAddr, conn *net.UDPConn) {
		if len(data) == 0 {
			return
		}
		if crypt != nil && crypt.Status == CsEncrypting {
			data = crypt.Decrypt(data)
		}
		LogUDPRaw("recv", remote.String(), data)
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
			s.udpGlobGetSources(b, remote, conn, crypt)
		case OpGlobGetSources2:
			s.udpGlobGetSources2(b, remote, conn, crypt)
		case OpGlobServStatReq:
			s.udpGlobServStatReq(b, remote, conn, crypt)
		case OpServerDescReq:
			if len(data) < 6 {
				s.udpServDescResOld(remote, conn, crypt)
			} else {
				s.udpServDescRes(b, remote, conn, crypt)
			}
		case OpGlobSearchReq:
			s.udpGlobSearchReq(b, remote, conn, crypt)
		case OpGlobSearchReq3:
			s.udpGlobSearchReq3(b, remote, conn, crypt)
		default:
			logging.Debugf("udp unknown opcode remote=%s opcode=0x%x", remote, code)
		}
	}
}

type tcpClient struct {
	server     *ServerRuntime
	conn       net.Conn
	packet     *Packet
	crypt      *TCPCrypt
	info       storage.ClientInfo
	logged     bool
	hasLowID   bool
	remoteHost string
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
	return &tcpClient{
		server:     server,
		conn:       conn,
		packet:     packet,
		crypt:      crypt,
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

func (c *tcpClient) run() {
	defer func() {
		if c.hasLowID {
			c.server.LowIDs.Remove(c.info.ID)
		}
		if c.logged {
			c.server.Storage.Disconnect(c.info)
		}
		_ = c.conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		if c.server.TCP.DisconnectTimeout > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(c.server.TCP.DisconnectTimeout))
		}
		n, err := c.conn.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
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
		LogTCPPacket("recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
		c.handleED2K(packet.Code, packet.Data)
	case PrZlib:
		LogTCPPacket("recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
		payload, err := InflateZlibPayload(packet.Data.Bytes())
		if err != nil {
			logging.Warnf("tcp zlib inflate failed remote=%s err=%v", c.remoteHost, err)
			return
		}
		LogTCPPacket("recv-decompressed", c.remoteHost, PrED2K, packet.Code, payload)
		c.handleED2K(packet.Code, NewBufferFromBytes(payload))
	default:
		LogTCPPacket("recv", c.remoteHost, packet.Protocol, packet.Code, packet.Data.Bytes())
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
	case OpGetSources, OpGetSourcesObfu:
		c.handleGetSources(data)
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
	c.info.Hash = req.Hash
	c.info.ID = req.ID
	c.info.Port = req.Port

	if c.server.Storage.IsConnected(c.info) {
		logging.Warnf("login request duplicate remote=%s", c.remoteHost)
		_ = c.conn.Close()
		return
	}

	firewalled := c.server.isFirewalled(c)
	if firewalled {
		c.hasLowID = true
		c.info.LowID = true
		c.sendServerMessage(c.server.TCP.MessageLowID)
		id, ok := c.server.LowIDs.Add(c)
		if !ok {
			_ = c.conn.Close()
			return
		}
		c.info.ID = id
	} else {
		c.hasLowID = false
		c.info.LowID = false
		c.info.ID = c.info.IPv4
	}
	c.handShake()
}

func (c *tcpClient) handShake() {
	storeID, err := c.server.Storage.Connect(c.info)
	if err != nil {
		logging.Warnf("storage connect failed remote=%s err=%v", c.remoteHost, err)
		_ = c.conn.Close()
		return
	}
	c.logged = true
	c.info.StoreID = storeID

	c.sendServerMessage(c.server.TCP.MessageLogin)
	c.sendServerMessage(fmt.Sprintf("server version %s (%s)", ENodeVersionStr, ENodeName))
	c.sendServerStatus()
	c.sendIDChange(c.info.ID)
	c.sendServerIdent()
}

func (c *tcpClient) handleOfferFiles(data *Buffer) {
	records, err := data.GetFileList()
	if err != nil {
		logging.Warnf("offer files parse failed remote=%s err=%v", c.remoteHost, err)
		return
	}
	for _, record := range records {
		file := fileFromRecord(record, c.info)
		c.server.Storage.AddFile(file, c.info)
	}
}

func (c *tcpClient) handleGetServerList() {
	c.sendServerList()
	c.sendServerIdent()
}

func (c *tcpClient) handleGetSources(data *Buffer) {
	hash := append([]byte(nil), data.Get(16)...)
	if len(hash) != 16 {
		return
	}
	size, err := data.GetUInt32LE()
	if err != nil {
		return
	}
	fileSize := uint64(size)
	if fileSize == 0 {
		v, err := data.GetUInt64LE()
		if err != nil {
			return
		}
		fileSize = v
	}
	sources := c.server.Storage.GetSources(hash, fileSize)
	if len(sources) == 0 {
		return
	}
	c.sendFoundSources(hash, sources)
}

func (c *tcpClient) handleSearchRequest(data *Buffer) {
	expr, err := ParseSearchExpr(data)
	if err != nil {
		return
	}
	files := c.server.Storage.FindBySearch(expr)
	if len(files) == 0 {
		return
	}
	c.sendSearchResult(files)
}

func (c *tcpClient) handleCallbackRequest(data *Buffer) {
	lowID, err := data.GetUInt32LE()
	if err != nil {
		return
	}
	v, ok := c.server.LowIDs.Get(lowID)
	if !ok {
		c.sendCallbackFailed()
		return
	}
	target, ok := v.(*tcpClient)
	if !ok {
		c.sendCallbackFailed()
		return
	}
	if err := target.sendCallbackRequested(c.info.IPv4, c.info.Port); err != nil {
		c.sendCallbackFailed()
	}
}

func (c *tcpClient) sendFoundSources(hash []byte, sources []storage.Source) {
	packet, err := BuildFoundSourcesPacket(hash, sources)
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
	LogTCPRaw("send", c.remoteHost, data)
	if c.crypt != nil && c.crypt.State == CsEncrypting {
		data = RC4Crypt(data, len(data), c.crypt.SendKey)
	}
	_, err := c.conn.Write(data)
	return err
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

func (s *ServerRuntime) udpGlobGetSources(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt) {
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
		_ = udpSend(conn, remote, packet.Bytes(), crypt)
	}
}

func (s *ServerRuntime) udpGlobGetSources2(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt) {
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
		_ = udpSend(conn, remote, packet.Bytes(), crypt)
	}
}

func (s *ServerRuntime) udpGlobServStatReq(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt) {
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
	_ = udpSend(conn, remote, packet.Bytes(), crypt)
}

func (s *ServerRuntime) udpServDescResOld(remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt) {
	packet, err := BuildServerDescResOldPacket(s.UDP.Name, s.UDP.Description)
	if err != nil {
		return
	}
	_ = udpSend(conn, remote, packet.Bytes(), crypt)
}

func (s *ServerRuntime) udpServDescRes(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt) {
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
	_ = udpSend(conn, remote, packet.Bytes(), crypt)
}

func (s *ServerRuntime) udpGlobSearchReq(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt) {
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
		_ = udpSend(conn, remote, packet.Bytes(), crypt)
	}
}

func (s *ServerRuntime) udpGlobSearchReq3(b *Buffer, remote *net.UDPAddr, conn *net.UDPConn, crypt *UDPCrypt) {
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
		_ = udpSend(conn, remote, packet.Bytes(), crypt)
	}
}

func udpSend(conn *net.UDPConn, remote *net.UDPAddr, data []byte, crypt *UDPCrypt) error {
	LogUDPRaw("send", remote.String(), data)
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
