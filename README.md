# eNode-go

Go port of the original `eNode` eD2K/eMule server codebase.

[中文说明](README.zh-CN.md)

Protocol doc: [Server <=> Client Communication (OP_ meanings)](docs/server-client-communication.md)

## Included

- Core eD2K protocol modules (`ed2k/*`)
- Runtime entrypoint (`cmd/enode/main.go`)
- YAML config loader (`config/*`)
- Storage engines:
  - `memory`
  - `mysql` (real `database/sql` + `go-sql-driver/mysql`)
  - `mongodb` (real official MongoDB Go driver)
- Unit tests for core modules
- Dockertest integration tests for real MySQL/Mongo backends

## Features

- TCP/UDP opcodes
- TCP/UDP protocol obfuscation
- Obfuscated lowID detection
- Lugdunum/eMule extended protocol
- gzip compression
- LowID callbacks
- NAT traversal server (`OP_VC_NAT_HEADER`, `OP_NAT_REGISTER`, `OP_NAT_SYNC2`)
- Files larger than 4 GiB
- Easy support for multiple storage engines

## NAT Traversal Transfer Screenshot

![NAT traversal transfer screenshot](images/E35D333390376E311EA081CAD69D85D7.png)

## Configuration

Runtime config is YAML:

- `enode.config.yaml`

Start command supports custom path:

```bash
go run ./cmd/enode -config enode.config.yaml
```

Full config field reference:

```yaml
name: "(TESTING!!!) eNode"   # Server name shown to clients
description: "eNode ..."     # Server description shown to clients
address: ""                  # Local bind address; default is 0.0.0.0
dynIp: "auto"                # Public advertised IP; auto resolves via testUrls
testUrls:                    # Used only when dynIp=auto, first valid IPv4 wins
  - "https://4.ipw.cn"
  - "https://ip.3322.net"
  - "https://api.ipify.org"
  - "https://checkip.amazonaws.com"

messageLowID: "You have LowID."   # Message sent to LowID clients
messageLogin: "Welcome to eNode!" # Message sent on login

noAssert: false              # Compatibility assert switch (normally false)
logLevel: "debug"            # Log level: debug|info|warn|error
logFile: "logs/enode.log"    # Log file path

supportCrypt: true           # Enable protocol obfuscation support
requestCrypt: true           # Request obfuscation from clients
requireCrypt: true           # Require obfuscation from clients
auxiliarPort: false          # Advertise auxiliary port capability
IPinLogin: false             # Include IP in login flow

tcp:
  port: 5555                 # Main TCP port
  portObfuscated: 5565       # Obfuscated TCP port (when supportCrypt=true)
  maxConnections: 1000000    # Max concurrent connections
  connectionTimeout: 2000    # Connect-stage timeout (ms)
  disconnectTimeout: 3600    # Idle disconnect timeout (s)
  allowLowIDs: true          # Allow LowID clients
  minLowID: 1                # Minimum allocated LowID
  maxLowID: 16777215         # Maximum allocated LowID

udp:
  port: 5559                 # Main UDP port
  portObfuscated: 5569       # Obfuscated UDP port
  getSources: true           # Enable UDP source queries
  getFiles: true             # Enable UDP file queries
  serverKey: 305419896       # Server key for UDP obfuscation/handshake

natTraversal:
  enabled: true              # Enable NAT traversal service
  port: 2004                 # NAT traversal UDP port
  registrationTTLSeconds: 30 # NAT registry TTL (seconds)

storage:
  engine: memory             # Storage engine: memory | mysql | mongodb
  mysql:
    host: localhost          # MySQL host
    port: 3306               # MySQL port
    user: enode              # MySQL user
    pass: password           # MySQL password
    database: enode          # MySQL database
    connections: 8           # MySQL connection pool cap
    deadlockDelay: 100       # Deadlock retry delay (ms)
  mongodb:
    host: 127.0.0.1          # MongoDB host (used when uri is empty)
    port: 27017              # MongoDB port (used when uri is empty)
    database: enode          # MongoDB database name
    uri: ""                  # MongoDB URI; takes precedence when set
```

`address` vs `dynIp`:
- `address` controls local bind/listen address on this machine.
- `dynIp` controls the public IP advertised to clients.

For MySQL:

```yaml
storage:
  engine: mysql
  mysql:
    host: localhost
    port: 3306
    user: enode
    pass: password
    database: enode
    connections: 8
```

For MongoDB:

```yaml
storage:
  engine: mongodb
  mongodb:
    uri: mongodb://localhost:27017
    database: enode
```

## Build & Test

Run all standard tests:

```bash
go test ./...
```

Run real DB integration tests (Docker required):

```bash
ENODE_INTEGRATION=1 go test ./storage -run Dockertest -v
```

This spins temporary MySQL and MongoDB containers, initializes schema/data, and verifies backend behavior end-to-end.

## To Do

- Better storage/indexing
- IPv6 support ([unofficial draft for eD2K IPv6 extension](http://piratenpad.de/p/ed2kIPv6))

## Thanks To

- David Xanatos

## Notes

- The original Node.js repository remains separate; this directory is the Go implementation.
- If Docker is unavailable, integration tests are skipped unless explicitly enabled.
