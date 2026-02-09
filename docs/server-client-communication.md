# Server <=> Client Communication (OP_* Meanings)

This document explains the main `OP_*` operation codes used by `eNode-go` and their expected direction.

## Protocol Basics

- Transport protocols:
  - `PR_ED2K (0xe3)`: normal eD2K packets
  - `PR_ZLIB (0xd4)`: compressed payloads
  - `PR_EMULE (0xc5)`: eMule-specific protocol family
  - `PR_NAT (0xf1)`: NAT traversal UDP protocol family
- TCP packet format (simplified): `protocol(1) + size(4) + opcode(1) + payload`
- UDP packet format (simplified): `protocol(1) + opcode(1) + payload`
- NAT UDP packet format: `protocol(1) + size(4, little-endian) + opcode(1) + payload`

## TCP OP Codes

| OP constant | Hex | Direction | Meaning |
|---|---:|---|---|
| `OP_LOGINREQUEST` | `0x01` | Client -> Server | Client login/session registration. |
| `OP_HELLO` | `0x01` | Server -> Client (handshake check client path) | Basic hello packet; same numeric code as login in different context. |
| `OP_HELLOANSWER` | `0x4c` | Peer -> Server/client helper | Response to `OP_HELLO` with node info/tags. |
| `OP_GETSERVERLIST` | `0x14` | Client -> Server | Request known server list. |
| `OP_OFFERFILES` | `0x15` | Client -> Server | Submit shared file/source list. |
| `OP_GETSOURCES` | `0x19` | Client -> Server | Request sources for a file. |
| `OP_GETSOURCES_OBFU` | `0x23` | Client -> Server | Obfuscated source request variant. |
| `OP_SEARCHREQUEST` | `0x16` | Client -> Server | Search query request. |
| `OP_CALLBACKREQUEST` | `0x1c` | Client -> Server | Ask server to callback a LowID client. |
| `OP_SERVERMESSAGE` | `0x38` | Server -> Client | Human-readable server message. |
| `OP_SERVERSTATUS` | `0x34` | Server -> Client | Current server counters/status. |
| `OP_IDCHANGE` | `0x40` | Server -> Client | Assign/update client ID and flags. |
| `OP_SERVERLIST` | `0x32` | Server -> Client | Response with known servers. |
| `OP_SERVERIDENT` | `0x41` | Server -> Client | Server identity/tags response. |
| `OP_FOUNDSOURCES` | `0x42` | Server -> Client | Source list for requested file. |
| `OP_FOUNDSOURCES_OBFU` | `0x44` | Server -> Client | Obfuscated found-sources variant (reserved/not fully wired). |
| `OP_SEARCHRESULT` | `0x33` | Server -> Client | Search results list. |
| `OP_CALLBACKREQUESTED` | `0x35` | Server -> LowID client | Notify LowID client to connect back. |
| `OP_CALLBACKFAILED` | `0x36` | Server -> Client | Callback target unavailable/failure. |

## UDP OP Codes

| OP constant | Hex | Direction | Meaning |
|---|---:|---|---|
| `OP_GLOBGETSOURCES` | `0x9a` | Client -> Server | UDP source query by hash. |
| `OP_GLOBGETSOURCES2` | `0x94` | Client -> Server | UDP source query with hash+size. |
| `OP_GLOBSERVSTATREQ` | `0x96` | Client -> Server | UDP server stats request. |
| `OP_SERVERDESCREQ` | `0xa2` | Client -> Server | UDP server description request. |
| `OP_GLOBSEARCHREQ` | `0x98` | Client -> Server | UDP search request. |
| `OP_GLOBSEARCHREQ3` | `0x90` | Client -> Server | Extended UDP search request (tree/tags). |
| `OP_GLOBFOUNDSOURCES` | `0x9b` | Server -> Client | UDP source response. |
| `OP_GLOBSERVSTATRES` | `0x97` | Server -> Client | UDP server stats response. |
| `OP_SERVERDESCRES` | `0xa3` | Server -> Client | UDP server description response. |
| `OP_GLOBSEARCHRES` | `0x99` | Server -> Client | UDP search results response. |

## NAT Traversal UDP OP Codes (`PR_NAT = 0xf1`)

| OP constant | Hex | Direction | Meaning |
|---|---:|---|---|
| `OP_NAT_REGISTER` | `0xe4` | Client -> NAT Server | Register/refresh client hash and observed endpoint. |
| `OP_NAT_REGISTER` | `0xe4` | NAT Server -> Client | Register ACK with server endpoint (`port(2, BE) + ip(4, BE)`). |
| `OP_NAT_SYNC2` | `0xe9` | Client -> NAT Server | Ask server to pair source hash with target hash (`srcHash(16)+connAck(4)+dstHash(16)`). |
| `OP_NAT_SYNC` | `0xe1` | NAT Server -> Client | Peer endpoint exchange (`peerIP(4, BE)+peerPort(2, BE)+peerHash(16)+connAck(4)`). |
| `OP_NAT_FAILED` | `0xe5` | NAT Server -> Client | Pairing failed (`reason(1) + targetHash(16)`; reason `0x01` = target not registered). |
| keepalive (non-`PR_NAT`) | n/a | Client -> NAT Server | Raw UDP heartbeat without NAT header; used only to refresh last-seen. |

## Payload Data Format

### Encoding Conventions

- Unless explicitly noted, integer fields are little-endian.
- `hash16`: fixed 16-byte client/file hash.
- `string`: `uint16 length + bytes`.
- `tags`: `uint32 count`, then repeated tag entries (see `ed2k/buffer.go`).
- `source entry`: `clientID(uint32) + clientPort(uint16)`.

### TCP Payloads (Implemented Here)

- `OP_LOGINREQUEST` (client -> server, parsed):
  - `hash16 + clientID(uint32) + clientPort(uint16) + tags`
- `OP_SERVERMESSAGE`:
  - `message(string)`
- `OP_SERVERSTATUS`:
  - `clients(uint32) + files(uint32)`
- `OP_IDCHANGE`:
  - `clientID(uint32) + tcpFlags(uint32)`
- `OP_SERVERLIST`:
  - `serverCount(uint8) + repeated(serverIP(uint32) + serverPort(uint16))`
- `OP_SERVERIDENT`:
  - `serverHash(hash16) + serverIP(uint32) + serverPort(uint16) + tags`
- `OP_FOUNDSOURCES`:
  - `fileHash(hash16) + sourceCount(uint8) + repeated(source entry)`
- `OP_SEARCHRESULT`:
  - `resultCount(uint32) + repeated(fileRecord)`
  - `fileRecord`: `fileHash(hash16) + sourceID(uint32) + sourcePort(uint16) + tags`
- `OP_CALLBACKREQUESTED`:
  - `targetIP(uint32) + targetPort(uint16)`
- `OP_CALLBACKFAILED`:
  - empty payload

### UDP Payloads (Implemented Here)

- `OP_GLOBFOUNDSOURCES`:
  - `fileHash(hash16) + sourceCount(uint8) + repeated(source entry)`
- `OP_GLOBSEARCHRES`:
  - one file per UDP packet:
  - `fileRecord` (`fileHash + sourceID + sourcePort + tags`)
- `OP_GLOBSERVSTATRES`:
  - `challenge(uint32)`
  - `users(uint32) + files(uint32)`
  - `maxConnections(uint32) + softLimit(uint32) + hardLimit(uint32)`
  - `udpFlags(uint32) + lowIDUsers(uint32)`
  - `udpPortObf(uint16) + tcpPortObf(uint16) + udpServerKey(uint32)`
- `OP_SERVERDESCRES` (old form):
  - `name(string) + description(string)`
- `OP_SERVERDESCRES` (extended form):
  - `challenge(uint32) + tags`

### NAT Payloads (`PR_NAT`)

- NAT packet envelope is different from regular UDP:
  - `protocol(1) + size(4, little-endian) + opcode(1) + payload`
- Field endianness:
  - NAT envelope `size`: little-endian
  - `peerIP/peerPort` and register ACK endpoint fields: big-endian
- `OP_NAT_REGISTER` (client -> server):
  - `userHash(hash16)` or `userHash(hash16) + stats(3 * uint16)`
- `OP_NAT_REGISTER` (server -> client):
  - `serverPort(uint16, BE) + serverIP(uint32, BE)`
- `OP_NAT_SYNC2`:
  - `srcHash(hash16) + connAck(uint32) + dstHash(hash16)`
- `OP_NAT_SYNC`:
  - `peerIP(uint32, BE) + peerPort(uint16, BE) + peerHash(hash16) + connAck(uint32)`
- `OP_NAT_FAILED`:
  - `reason(uint8) + targetHash(hash16)` (implemented reason: `0x01`)

## Notes

- Exact field encoding for each payload is implemented in:
  - `ed2k/tcpoperations.go`
  - `ed2k/udpoperations.go`
  - `ed2k/packet.go`
  - `ed2k/nattraversal.go`
