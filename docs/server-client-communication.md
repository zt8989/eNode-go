# Server <=> Client Communication (OP_* Meanings)

This document explains the main `OP_*` operation codes used by `eNode-go` and their expected direction.

## Protocol Basics

- Transport protocols:
  - `PR_ED2K (0xe3)`: normal eD2K packets
  - `PR_ZLIB (0xd4)`: compressed payloads
  - `PR_EMULE (0xc5)`: eMule-specific protocol family
- TCP packet format (simplified): `protocol(1) + size(4) + opcode(1) + payload`
- UDP packet format (simplified): `protocol(1) + opcode(1) + payload`

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

## Notes

- Exact field encoding for each payload is implemented in:
  - `ed2k/tcpoperations.go`
  - `ed2k/udpoperations.go`
  - `ed2k/packet.go`
