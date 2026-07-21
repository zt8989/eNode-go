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
	Name        string
	Description string
	// Address is the bind address, and may be the 0.0.0.0 wildcard.
	Address string
	// AdvertisedIP is the address published to clients in OP_SERVERIDENT. It is
	// separate from Address because the wildcard is a valid thing to bind but
	// encodes as IP 0, which tells a client nothing. Empty falls back to Address.
	AdvertisedIP         string
	Port                 uint16
	Flags                uint32
	Hash                 []byte
	MessageLogin         string
	MessageLowID         string
	ConnectionTimeout    time.Duration
	DisconnectTimeout    time.Duration
	ServerStatusInterval time.Duration
	// CounterCacheTTL bounds how stale the advertised client/file counts may be.
	// Zero uses defaultCounterCacheTTL.
	CounterCacheTTL time.Duration
	AllowLowIDs     bool
	SupportCrypt    bool
	// MinLowID and MaxLowID bound the LowID allocation range (tcp.minLowID /
	// tcp.maxLowID). Zero means "use the default", resolved in NewLowIDClients.
	MinLowID uint32
	MaxLowID uint32
}

type UDPRuntimeConfig struct {
	Name        string
	Description string
	DynIP       string
	UDPFlags    uint32
	// GetSources and GetFiles gate the extended UDP opcodes. Previously they
	// existed only on UDPServerConfig, where BuildUDPFlags used them to *advertise*
	// support — so a server with getSources disabled cleared the flag and then
	// answered anyway. Conforming clients respect the advertised flag, so the
	// exposure was precisely to the abusive ones the option exists to stop.
	GetSources     bool
	GetFiles       bool
	UDPPortObf     uint16
	TCPPortObf     uint16
	UDPServerKey   uint32
	MaxConnections uint32
}

type ServerRuntime struct {
	TCP      TCPRuntimeConfig
	UDP      UDPRuntimeConfig
	Storage  storage.Engine
	LowIDs   *LowIDClients
	NAT      *NATTraversalHandler
	counters *counterCache
}

func NewServerRuntime(tcp TCPRuntimeConfig, udp UDPRuntimeConfig, store storage.Engine) *ServerRuntime {
	if tcp.ServerStatusInterval <= 0 {
		tcp.ServerStatusInterval = defaultServerStatusInterval
	}
	return &ServerRuntime{
		TCP:      tcp,
		UDP:      udp,
		Storage:  store,
		LowIDs:   NewLowIDClients(tcp.AllowLowIDs, tcp.MinLowID, tcp.MaxLowID),
		counters: newCounterCache(store, tcp.CounterCacheTTL),
	}
}

func (s *ServerRuntime) TCPHandler(enableCrypt bool) func(net.Conn) {
	return func(conn net.Conn) {
		client := newTCPClient(s, conn, enableCrypt)
		client.run()
	}
}

// advertisedAddress is the address published to clients, falling back to the
// bind address when none was configured. Callers that need the *bind* address
// (probeClient's LocalAddr) must keep using TCP.Address.
func (s *ServerRuntime) advertisedAddress() string {
	if s.TCP.AdvertisedIP != "" {
		return s.TCP.AdvertisedIP
	}
	return s.TCP.Address
}

func (s *ServerRuntime) SetNATHandler(handler *NATTraversalHandler) {
	s.NAT = handler
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
		if s.NAT != nil {
			if data[0] == PrNat || len(data) == 1 {
				s.NAT.HandlePacket(data, remote, conn, crypt)
				if data[0] == PrNat {
					return
				}
			}
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
		// Gated per opcode, not by one shared switch: each is advertised by its
		// own flag, and the two below are deliberately ungated because they carry
		// no such flag — refusing them would make the server invisible in server
		// lists.
		switch code {
		case OpGlobGetSources:
			if !s.udpOpcodeEnabled(s.UDP.GetSources, code, remote) {
				return
			}
			s.udpGlobGetSources(b, remote, conn, crypt, module)
		case OpGlobGetSources2:
			if !s.udpOpcodeEnabled(s.UDP.GetSources, code, remote) {
				return
			}
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
			if !s.udpOpcodeEnabled(s.UDP.GetFiles, code, remote) {
				return
			}
			s.udpGlobSearchReq(b, remote, conn, crypt, module)
		case OpGlobSearchReq3:
			if !s.udpOpcodeEnabled(s.UDP.GetFiles, code, remote) {
				return
			}
			s.udpGlobSearchReq3(b, remote, conn, crypt, module)
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
	module     string
	writeMu    sync.Mutex
	closeMu    sync.Mutex
	remoteHost string
	statusStop chan struct{}

	// infoMu guards info, logged and hasLowID. The connection's own goroutine
	// writes them during login, but two other goroutines read them: the periodic
	// status ticker (logged) and any peer handling OP_CALLBACKREQUEST, which
	// reaches this client through the shared LowIDs table.
	infoMu   sync.RWMutex
	info     storage.ClientInfo
	logged   bool
	hasLowID bool

	closeReason string
}

// snapshotInfo returns a copy of the client's identity, safe to read from any
// goroutine. Hash is copied too: returning the slice header would let the caller
// alias a field the owning goroutine may still rewrite.
func (c *tcpClient) snapshotInfo() storage.ClientInfo {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	info := c.info
	if info.Hash != nil {
		info.Hash = append([]byte(nil), info.Hash...)
	}
	return info
}

func (c *tcpClient) isLogged() bool {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return c.logged
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
		c.infoMu.RLock()
		hadLowID, wasLogged := c.hasLowID, c.logged
		c.infoMu.RUnlock()
		info := c.snapshotInfo()
		if hadLowID {
			c.server.LowIDs.Remove(info.ID)
		}
		if wasLogged {
			c.server.Storage.Disconnect(info)
		}
		_ = c.conn.Close()
		logging.Infof("tcp session closed remote=%s id=%d lowID=%t storeID=%d reason=%s",
			c.remoteHost, info.ID, info.LowID, info.StoreID, c.getCloseReason())
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
		state := c.crypt.State()
		switch state {
		case CsUnknown, CsNegotiating:
			// Inspect the protocol byte before assuming obfuscation. A plaintext
			// client may legitimately connect to the obfuscated port; feeding its
			// login straight into negotiate() would consume the payload as
			// [marker][96-byte DH A][pad], derive keys from it, and wedge the
			// session. The original checks the protocol byte first for this
			// reason (eNode/ed2k/packet.js:105-129).
			if state == CsUnknown && len(data) > 0 && IsProtocol(data[0]) {
				logging.Debugf("tcp plaintext on obfuscated port remote=%s proto=0x%x", c.remoteHost, data[0])
				c.crypt.SetState(CsNone)
				break
			}
			rest, err := c.crypt.ProcessData(NewBufferFromBytes(data))
			if err != nil {
				// The stream is unrecoverable once negotiation fails: state stays
				// CsNegotiating and every later chunk fails the same way, so the
				// peer would linger until disconnectTimeout (3600s by default).
				logging.Warnf("tcp crypt error remote=%s err=%v", c.remoteHost, err)
				c.closeWithReason(fmt.Sprintf("crypt-handshake-failed: %v", err))
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
		if err := c.packet.Init(buf); err != nil {
			// An oversized declaration is never legitimate and would otherwise
			// allocate the declared size, so drop the peer rather than resync.
			if errors.Is(err, ErrPacketTooLarge) {
				logging.Warnf("tcp packet too large remote=%s err=%v", c.remoteHost, err)
				c.closeWithReason("packet-too-large")
			}
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
			// A compression ratio that overshoots the ceiling is a zlib bomb, not
			// a corrupt stream: drop the peer instead of waiting for the next one.
			if errors.Is(err, ErrInflatedTooLarge) {
				c.closeWithReason("zlib-bomb")
			}
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

	// One login per connection. OP_LOGINREQUEST is dispatched at any point in the
	// session, and a repeat used to overwrite c.info.ID while the previously
	// allocated LowID stayed in the table pointing at this client — the cleanup
	// path frees only the last one, so a socket looping logins drained the pool.
	if c.isLogged() {
		logging.Warnf("duplicate login on an established session remote=%s", c.remoteHost)
		c.closeWithReason("already-logged-in")
		return
	}

	// Reject the new connection when this user hash is already online, rather
	// than evicting the existing session. The hash is public — it is broadcast in
	// OP_HELLO and handed out in OP_FOUNDSOURCES_OBFU — so eviction let any peer
	// disconnect any user at will. The original rejects too
	// (eNode/ed2k/tcpoperations.js:233-243), and checks before the firewall probe
	// so a duplicate does not cost a dial-back.
	if len(req.Hash) == 16 && c.server.Storage.IsConnected(storage.ClientInfo{Hash: req.Hash}) {
		logging.Warnf("login rejected remote=%s hash=%x: already connected", c.remoteHost, req.Hash)
		c.sendServerMessage("Already connected from another session.")
		c.closeWithReason("duplicate-login")
		return
	}

	c.infoMu.Lock()
	c.info.Hash = req.Hash
	c.info.ID = req.ID
	c.info.Port = req.Port
	// Record the client's obfuscation capabilities so OP_FOUNDSOURCES_OBFU can
	// re-publish them per source. Absent tag → 0, i.e. no crypt advertised.
	c.info.CryptOptions = cryptOptionsFromLoginFlags(loginFlags(req.Tags))
	ipv4, port := c.info.IPv4, c.info.Port
	c.infoMu.Unlock()

	firewalled := c.server.isFirewalled(c)
	logging.Debugf("login decision remote=%s requestedID=%d firewalled=%t", c.remoteHost, req.ID, firewalled)
	if firewalled {
		c.infoMu.Lock()
		c.hasLowID = true
		c.info.LowID = true
		c.infoMu.Unlock()
		c.sendServerMessage(c.server.TCP.MessageLowID)

		// AddByEndpoint publishes this *tcpClient into a table other goroutines
		// read. IPv4 and Port are already settled above, which is what those
		// readers use; the ID that comes back is written under infoMu below, so
		// a concurrent reader sees either the old or the new value, never a torn
		// one.
		id, ok := c.server.LowIDs.AddByEndpoint(ipv4, port, c)
		if !ok {
			c.closeWithReason("lowid-pool-exhausted")
			return
		}
		c.infoMu.Lock()
		c.info.ID = id
		c.infoMu.Unlock()
	} else {
		c.infoMu.Lock()
		c.hasLowID = false
		c.info.LowID = false
		c.info.ID = c.info.IPv4
		c.infoMu.Unlock()
	}
	info := c.snapshotInfo()
	logging.Infof("login accepted remote=%s assignedID=%d lowID=%t port=%d", c.remoteHost, info.ID, info.LowID, info.Port)
	c.handShake()
}

func (c *tcpClient) handShake() {
	storeID, err := c.server.Storage.Connect(c.snapshotInfo())
	if err != nil {
		logging.Warnf("storage connect failed remote=%s err=%v", c.remoteHost, err)
		c.closeWithReason(fmt.Sprintf("storage-connect-failed: %v", err))
		return
	}
	c.infoMu.Lock()
	c.logged = true
	c.info.StoreID = storeID
	c.infoMu.Unlock()
	info := c.snapshotInfo()
	logging.Infof("login handshake complete remote=%s storeID=%d id=%d lowID=%t", c.remoteHost, info.StoreID, info.ID, info.LowID)

	c.sendServerMessage(c.server.TCP.MessageLogin)
	c.sendServerMessage(fmt.Sprintf("server version %s (%s)", ENodeVersionStr, ENodeName))
	c.sendServerStatus()
	c.startPeriodicServerStatus()
	c.sendIDChange(info.ID)
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
				if c.isLogged() {
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
	// One snapshot for the whole batch: the identity cannot change mid-batch,
	// and taking it per file would lock once per offered file.
	info := c.snapshotInfo()
	for _, record := range records {
		file := fileFromRecord(record, info)
		c.server.Storage.AddFile(file, info)
	}
	limit := len(records)
	if limit > maxOfferFilesLog {
		limit = maxOfferFilesLog
	}
	for i := 0; i < limit; i++ {
		record := records[i]
		file := fileFromRecord(record, info)
		logging.Debugf("offer file remote=%s idx=%d hash=%x name=%q size=%d type=%q sourceID=%d sourcePort=%d",
			c.remoteHost, i, record.Hash, file.Name, file.Size, file.Type, info.ID, info.Port)
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
	// Sent even when empty, matching the original's unconditional reply. Unlike
	// OP_SEARCHRESULT this fixes no client-side stall — OP_FOUNDSOURCES has no
	// timeout in eMule — but it keeps the two TCP reply paths symmetrical.
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
	// A zero-result reply must still be sent. OP_SEARCHRESULT is the only packet
	// that reaches eMule's LocalEd2kSearchEnd, which is what cancels the 50 s
	// local-search timer — on silence the client sits in "Searching…" for the
	// full timeout and then gives up without ever showing "0 results".
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
	// target belongs to another connection's goroutine, so its identity is read
	// through the snapshot accessor rather than directly.
	targetInfo := target.snapshotInfo()
	self := c.snapshotInfo()
	c.debugPayloadf("tcp payload parsed remote=%s opcode=OP_CALLBACKREQUEST lowID=%d targetIPv4=%d targetPort=%d",
		c.remoteHost, lowID, targetInfo.IPv4, targetInfo.Port)
	if err := target.sendCallbackRequested(self.IPv4, self.Port); err != nil {
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
	clients, files := c.server.counters.Counts()
	packet, err := BuildServerStatusPacket(clients, files)
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
		Address:     c.server.advertisedAddress(),
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
	// writeRaw is reachable from goroutines other than this connection's own —
	// the status ticker and a peer's OP_CALLBACKREQUEST both land here — so the
	// state and the key must be read together, under the crypt lock.
	if c.crypt != nil {
		if key, encrypting := c.crypt.SendCipher(); encrypting {
			data = RC4Crypt(data, len(data), key)
		}
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
	info := client.snapshotInfo()
	if info.Port == 0 {
		return false, fmt.Errorf("client port is 0")
	}
	addr := net.JoinHostPort(client.remoteHost, fmt.Sprintf("%d", info.Port))
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
	cli.Hash = client.snapshotInfo().Hash

	if enableCrypt {
		pad, err := RandBuf(Rand(0xff))
		if err != nil {
			return false, err
		}
		handshake, err := cli.BuildHandshake(RandProtocol(), RandUint32(), pad)
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
		// The peer here is the client being probed: it chose the address we
		// dialed and it controls every byte coming back. Without this ceiling it
		// can declare a huge size, then dribble bytes until the deadline while
		// the loop below never completes a packet and this slice grows unbounded.
		if len(buffer) > maxHelloAnswerBytes {
			return false, fmt.Errorf("hello answer exceeded %d bytes", maxHelloAnswerBytes)
		}

		for {
			if len(buffer) < 6 {
				break
			}
			if buffer[0] != PrED2K {
				return false, fmt.Errorf("bad protocol 0x%x", buffer[0])
			}
			size := int(binary.LittleEndian.Uint32(buffer[1:5]))
			// Same ceiling Packet.Init applies on the inbound path; this reader
			// reimplements the framing and so needs it too.
			if size > 0 && size-1 > MaxTCPPacketSize {
				return false, fmt.Errorf("%w: declared=%d max=%d", ErrPacketTooLarge, size-1, MaxTCPPacketSize)
			}
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
	// Cached: this handler is unauthenticated and unthrottled, so serving it
	// straight from the database made a status flood cost two full table scans
	// per datagram.
	clients, files := s.counters.Counts()
	packet, err := BuildGlobServStatResPacket(challenge, UDPConfig{
		Name:           s.UDP.Name,
		Description:    s.UDP.Description,
		DynIP:          s.UDP.DynIP,
		UDPFlags:       s.UDP.UDPFlags,
		UDPPortObf:     s.UDP.UDPPortObf,
		TCPPortObf:     s.UDP.TCPPortObf,
		UDPServerKey:   s.UDP.UDPServerKey,
		MaxConnections: s.UDP.MaxConnections,
	}, clients, files, int(s.LowIDs.Count()))
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
	// GetTags aborts mid-loop on a malformed tag and Buffer has no rewind, so
	// discarding this error left the read pointer at an arbitrary offset inside
	// a half-consumed tag — and ParseSearchExpr then built a query out of tag
	// payload bytes. Bail instead; the tag block is mandatory for this opcode,
	// so a failure here means the datagram is not parseable.
	if _, err := b.GetTags(); err != nil {
		logging.Warnf("udp glob search tags decode failed remote=%s err=%v", remote, err)
		return
	}
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
	if v, ok := tagUint32(record.Tags, "sources"); ok {
		file.Sources = v
	}
	// storage.File.Completed is a per-source boolean on the way in (the engines
	// store it as sources.complete) and a per-file aggregate on the way out
	// (recomputed as SUM(complete)). Only the (id, port) sentinel says anything
	// about *this* source, so it is the only thing allowed to set it.
	//
	// The "completesources" tag is the client's count of OTHER complete sources
	// it knows of. Feeding it in here meant a client that had the whole file but
	// knew of no other complete copy — legal, and it sends completesources=0 —
	// had its own completeness discarded. Letting a client-supplied count reach
	// a boolean column also let it inflate files.completed for a file it does
	// not have, so the tag is advisory and deliberately ignored.
	if record.Complete {
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
	if v, ok := tagUint32(record.Tags, "length"); ok {
		file.Runtime = v
	}
	if v, ok := tagUint32(record.Tags, "bitrate"); ok {
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

// udpOpcodeEnabled reports whether an extended UDP opcode may be served, and
// logs the refusal. Extended UDP is the cheapest amplification surface the
// server has — one small datagram can trigger a source lookup per hash — so a
// refusal is worth seeing in the log.
func (s *ServerRuntime) udpOpcodeEnabled(enabled bool, code uint8, remote *net.UDPAddr) bool {
	if enabled {
		return true
	}
	logging.Debugf("udp opcode disabled by config remote=%s opcode=0x%x", remote, code)
	return false
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

// loginFlags returns the CT_SERVER_FLAGS capability bitmask (tag "flags",
// code 0x20) from an OP_LOGINREQUEST tag set, or 0 if the client sent none.
// eMule packs its zlib/unicode/large-file and crypt capabilities here
// (srchybrid/ServerConnect.cpp). Integer tags decode to uint64; truncating to
// uint32 keeps every real flag bit — saturating (as tagUint32 does for magnitude
// fields) would be wrong for a bitmask, setting bits the client never advertised.
func loginFlags(tags []NamedTag) uint32 {
	for _, t := range tags {
		if t.Name != "flags" {
			continue
		}
		if v, ok := t.Value.(uint64); ok {
			return uint32(v)
		}
		return 0
	}
	return 0
}

// cryptOptionsFromLoginFlags maps the login capability bits to the per-source
// OP_FOUNDSOURCES_OBFU options byte: 0x01 supports, 0x02 requests, 0x04 requires
// obfuscation (srchybrid/ServerSocket.cpp:558-560).
func cryptOptionsFromLoginFlags(flags uint32) byte {
	var b byte
	if flags&FlagSupportCrypt != 0 {
		b |= 0x01
	}
	if flags&FlagRequestCrypt != 0 {
		b |= 0x02
	}
	if flags&FlagRequireCrypt != 0 {
		b |= 0x04
	}
	return b
}
