# IPv6 Client Implementation Spec (eNode-go)

How an eD2K/eMule client connects to eNode-go over IPv6 and exchanges IPv6
sources. This describes the **server's observable behaviour** — everything here is
implemented in eNode-go and byte-compatible with the eMuleAI / eMuleQt MOD-tag
scheme (`CT_MOD_*`, tag family `0xA0`–`0xAF`).

An IPv4-only client needs to do nothing: every classic packet is byte-identical
to the pre-IPv6 server. IPv6 is entirely additive and opt-in.

---

## 0. Constants

| Name | Value | Where |
|---|---|---|
| `CT_MOD_IP_V6` | tag `0xAE`, type `TAGTYPE_HASH` (0x01), 16 bytes | `OP_LOGINREQUEST` (client→server) |
| `CT_MOD_SVR_IP_V6` | tag `0xAF`, type `TAGTYPE_HASH`, 16 bytes | `OP_SERVERIDENT` (server→client) |
| `SRV_TCPFLG_IPV6` | `0x00004000` | `OP_IDCHANGE` / `OP_SERVERIDENT` flags word |
| `SRV_UDPFLG_IPV6` | `0x00004000` | `OP_GLOBSERVSTATRES` UDP flags word |
| `SRVCAP_IPV6` (optional) | `0x1000` | `CT_SERVER_FLAGS` (0x20) login tag |
| IPv6 source sentinel | ClientID `0xFFFFFFFF` | `OP_FOUNDSOURCES(_OBFU)`, `OP_GLOBFOUNDSOURCES` |
| `OP_GETSOURCES_IPV6` | `0x24` | client→server, TCP |
| `OP_FOUNDSOURCES_IPV6` | `0x25` | server→client, TCP |
| `OP_GLOBGETSOURCES_IPV6` | `0xA5` | client→server, UDP |
| `OP_GLOBFOUNDSOURCES_IPV6` | `0xA6` | server→client, UDP |
| `OP_CALLBACKREQUESTED_IPV6` | `0x26` | server→client, TCP |

**Byte order:** every 16-byte IPv6 field is the raw `in6_addr` in network byte
order (big-endian, the order `inet_pton` produces and a textual `2001:db8::1`
reads left to right). No swapping. Send a genuine IPv6 in the 16-byte field and an
IPv4 in the existing 32-bit ClientID/IP fields — never an IPv4-mapped
(`::ffff:a.b.c.d`) form in a 16-byte field, since it will not compare equal to the
plain IPv4 on the peer side.

---

## 1. Transport: reaching the server over IPv6

eNode-go binds a **dual-stack** listener (single socket, `[::]`, `IPV6_V6ONLY=0`)
when `ipv6.enabled` (the default). It accepts both IPv4 and IPv6 client
connections on the same TCP and UDP ports. No separate v6 port.

A client that wants to connect over IPv6 needs, on its own side:

- an `AF_INET6` (dual-stack) socket for the server TCP and UDP connections;
- `AAAA` DNS resolution for a server given by hostname;
- a 16-byte IPv6 field in its server list / `server.met` equivalent, not a
  `uint32` IP.

A client that connects over IPv4 keeps working unchanged and may still advertise
its IPv6 (see §2) so it can be published as a v6 source.

---

## 2. Announcing IPv6 capability to the server

Two independent signals; either marks the session as "understands the IPv6 source
formats" (the server calls this *sentinel-safe*):

1. **Connect over IPv6.** A session whose TCP connection arrives on an IPv6
   address is treated as v6-capable automatically.
2. **Send `CT_MOD_IP_V6` in `OP_LOGINREQUEST`.** Add a hash tag carrying your
   public IPv6 and bump the login tag count. This is exactly what eMuleAI sends
   (`ServerConnect.cpp`).

Login tag on the wire (classic tag format — the server has not yet parsed your
`SRVCAP_NEWTAGS` when it reads the login tags, so use classic form):

```
01            TAGTYPE_HASH
01 00         name length = 1 (LE uint16)
AE            CT_MOD_IP_V6
<16 bytes>    your public IPv6, network byte order
```

Only send it for a **genuinely public** IPv6 (global unicast, not loopback,
link-local `fe80::/10`, or ULA `fc00::/7`). The server validates and drops a
non-public value, but still treats the tag's presence as the capability signal.

Optionally also set `SRVCAP_IPV6 (0x1000)` in the `CT_SERVER_FLAGS (0x20)` login
tag. This lets you announce "I speak the extension" even before you have a public
IPv6 to put in `0xAE`. The server reads `CT_SERVER_FLAGS` as a uint32.

> **Hard coordination rule.** Do **not** advertise v6 capability (connect over
> IPv6, or send `CT_MOD_IP_V6`) unless your client also implements the sentinel
> parser in §4. A sentinel-safe session may receive `0xFFFFFFFF` sentinel sources
> inside a classic `OP_FOUNDSOURCES`; a client that advertises capability but
> cannot parse the sentinel will desync its source list.

### ID assignment for IPv6-only clients

An ed2k ClientID is 32 bits and a HighID *is* the packed IPv4, so a client with no
usable IPv4 can never get a HighID. eNode-go assigns such a client a **LowID**
unconditionally and reaches it via its IPv6 (published as a v6 source). Such a
client can also drive and receive **IPv6 LowID callbacks** (§7). A dual-stack
client with a routable IPv4 still gets a HighID as usual.

---

## 3. Reading the server's IPv6 capability

- **Flags word.** `SRV_TCPFLG_IPV6 (0x4000)` in `OP_IDCHANGE` / `OP_SERVERIDENT`
  and `SRV_UDPFLG_IPV6 (0x4000)` in `OP_GLOBSERVSTATRES` indicate the server
  supports the IPv6 extension. Treat unknown flag bits as reserved and ignore
  them, as eMule does.
- **Server's own IPv6.** `OP_SERVERIDENT` carries a `CT_MOD_SVR_IP_V6 (0xAF)`
  hash tag (16 bytes) when the server has a public IPv6. Parse it position-
  agnostically among the ident tags; unknown tags before/after it must be
  consumed by type and skipped (a `TAGTYPE_HASH` tag is 16 bytes). This is
  informational — you still reach the server on the same address you connected to.

---

## 4. Receiving IPv6 sources

Two formats. Implement **both** to be fully interoperable.

### 4a. Sentinel form — inside classic `OP_FOUNDSOURCES` / `OP_FOUNDSOURCES_OBFU`

The server sends this to a sentinel-safe session (see §2). A source whose only
routable address is IPv6 (a v6-only source, or a LowID source with a reachable
IPv6) is encoded with the ClientID sentinel `0xFFFFFFFF` followed by 16 IPv6
bytes. Per-source layout:

```
uint32 clientId                       // 0xFFFFFFFF marks an IPv6 source
uint16 port
[_OBFU only]        uint8  cryptOptions
[_OBFU && (cryptOptions & 0x80)]  uint8[16] userHash
[clientId == 0xFFFFFFFF]          uint8[16] ipv6   // ALWAYS the last field
```

The 16 IPv6 bytes come **after** the obfuscation fields. When you read
`clientId == 0xFFFFFFFF`, read the 16 bytes and create a source with that IPv6 and
the given port. A source with a real HighID (routable IPv4) is never sent as a
sentinel — you get its IPv4 form and should prefer it.

> A client that does not implement this branch **must not** be sentinel-safe (do
> not connect over IPv6 and do not send `CT_MOD_IP_V6`). Skipping the ClientID
> without consuming the 16 bytes desyncs the rest of the source list.

### 4b. Tag-block form — `OP_FOUNDSOURCES_IPV6` (0x25) / `OP_GLOBFOUNDSOURCES_IPV6` (0xA6)

The richer, unconditionally-safe format. You opt in by sending the request opcode;
the server replies in the extended layout only to a client that asked for it, so
there is no desync risk for anyone else.

Request (`OP_GETSOURCES_IPV6 0x24` TCP, `OP_GLOBGETSOURCES_IPV6 0xA5` UDP): same
payload as the classic `OP_GETSOURCES2` — `hash16` + file size (a zero `uint32`
size means a `uint64` size follows). UDP may repeat `hash16 + size` per file.

Reply:

```
hash16 fileHash
uint8  count
per source:
    uint32 clientId       // real ClientID, or 0xFFFFFFFF for a v6-only source
    uint16 port
    uint8  tagCount
    tags…                 // standard eD2K tags, uint8-counted
```

Recognised tags in the block:

| Tag | Value / type | Meaning |
|---|---|---|
| `CT_MOD_IP_V6` | `0xAE`, `TAGTYPE_HASH` (16 bytes) | the source's public IPv6 |

A source with no reachable IPv6 has `tagCount = 0` (just `clientId`+`port`), so the
block is a strict superset of the classic list. **Skip unknown tags by type** —
the block is forward-compatible and may gain tags (e.g. buddy IPv6, crypt options)
later.

> **Tag-type safety.** The block uses only `TAGTYPE_HASH` / `TAGTYPE_UINT8` and
> other length-determinable types — never `TAGTYPE_BOOL (0x05)` or
> `TAGTYPE_BOOLARRAY (0x06)`, which some parsers cannot length-skip.

### UDP framing

The server sends **one file block per datagram** for `OP_GLOBFOUNDSOURCES`. Do not
assume the vanilla `count * (4 + 2)` skip stride when coalescing — a sentinel
source carries extra bytes. The sentinel form is only ever sent over UDP to a
sender whose query arrived over IPv6; the tag-block form is sent only in reply to
`OP_GLOBGETSOURCES_IPV6`.

---

## 5. Choosing an address to connect to a source

When a source offers both an IPv4 (HighID) and an IPv6, prefer the family you have
working connectivity on; the server prefers giving you the IPv4 form when you have
a usable IPv4, and the IPv6 sentinel/tag when the source has no routable IPv4. A
v6-only source (`clientId == 0xFFFFFFFF`) is reachable only over IPv6.

---

## 6. What the server does not do

- **No IPv6 in NAT traversal.** The `PR_NAT (0xF1)` protocol is IPv4-only; a
  globally-addressable IPv6 peer does not need it.
- **No IPv6 in `OP_SERVERLIST`.** Advertised peer servers are IPv4.

---

## 7. IPv6 LowID callbacks

A LowID callback lets a firewalled **target** be reached: a **requester** asks the
server to tell the target to connect *back* to the requester. Classic
`OP_CALLBACKREQUESTED (0x35)` carries `uint32 ip + uint16 port` (the requester's
IPv4), so it only works when the requester is directly reachable over IPv4 (HighID).
A requester whose only routable address is IPv6 — v6-only, or LowID over IPv4 —
could not be called back at all. eNode-go now closes that gap.

### Request (unchanged)

The requester still sends `OP_CALLBACKREQUEST (0x1C)` `<target LowID:uint32>`. The
LowID is the server-assigned 32-bit id; it is family-agnostic and needs no change.

### The server's family choice

The server picks the callback family from the **requester's** reachability, as two
independent checks:

1. If the requester has a HighID (a routable IPv4), the server sends the classic
   `OP_CALLBACKREQUESTED (0x35)` — byte-identical to before.
2. Otherwise (requester LowID over IPv4, or IPv4 `0`), if the requester has a
   **reachable public IPv6** and the target session is **v6-capable** (§2), the
   server sends `OP_CALLBACKREQUESTED_IPV6 (0x26)` so the target calls back over
   IPv6.
3. If neither applies, the server sends `OP_CALLBACKFAILED (0x36)`.

### `OP_CALLBACKREQUESTED_IPV6 (0x26)` — server → target

```
uint8      opcode = 0x26
uint8[16]  ipv6        // the requester's public IPv6, network byte order
uint16     port        // the requester's port (LE)
```

It is the classic packet widened from a 4-byte IPv4 to a 16-byte `in6_addr`, with
**no** crypt-options/userhash trailer (eNode-go's classic `0x35` emitter has none
either). On receipt, build the callback client from the 16 IPv6 bytes and the port
and connect to it over IPv6, exactly as you would `TryToConnect()` on the IPv4
address from `0x35`.

> **Capability gate.** The server only sends `0x26` to a session it knows is
> v6-capable (connected over IPv6, or sent `CT_MOD_IP_V6` at login — §2). A client
> that is not v6-capable never receives it, and a legacy client drops the unknown
> `0x26` opcode in its `ProcessPacket` default, so there is no desync risk.
