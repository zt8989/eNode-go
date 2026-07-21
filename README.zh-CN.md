# eNode-go

原始 `eNode` eD2K/eMule 服务端项目的 Go 版本实现。

[English README](README.md)

## 包含内容

- 核心 eD2K 协议模块（`ed2k/*`）
- 运行入口（`cmd/enode/main.go`）
- YAML 配置加载器（`config/*`）
- 存储引擎：
  - `memory`
  - `mysql`（基于 `database/sql` + `go-sql-driver/mysql`）
  - `mongodb`（官方 MongoDB Go 驱动）
- 核心模块单元测试
- 面向真实 MySQL/Mongo 的 Dockertest 集成测试

## 特性

- TCP/UDP 操作码支持
- TCP/UDP 协议混淆
- 混淆低 ID（LowID）检测
- Lugdunum/eMule 扩展协议
- gzip 压缩
- LowID 回调（IPv4；当请求方仅能通过 IPv6 到达时，使用 `OP_CALLBACKREQUESTED_IPV6`）
- NAT 穿透服务端（`OP_VC_NAT_HEADER`、`OP_NAT_REGISTER`、`OP_NAT_SYNC2`）
- 支持大于 4 GiB 的文件
- 易于扩展多种存储引擎

## NAT Traversal 传输截图

![NAT traversal 传输截图](docs/images/E35D333390376E311EA081CAD69D85D7.png)

## 配置

运行配置使用 YAML：

- `enode.config.yaml`

支持通过参数指定配置路径：

```bash
go run ./cmd/enode -config enode.config.yaml
```

完整配置说明（字段含义）：

```yaml
name: "(TESTING!!!) eNode"   # 服务器名称，对外展示
description: "eNode ..."     # 服务器描述，对外展示
address: ""                  # 本地监听地址；空时默认 0.0.0.0
dynIp: "auto"                # 对外通告 IP；auto 时通过 testUrls 动态探测
testUrls:                    # dynIp=auto 时依次请求，取第一个可用 IPv4
  - "https://4.ipw.cn"
  - "https://ip.3322.net"
  - "https://api.ipify.org"
  - "https://checkip.amazonaws.com"

messageLowID: "You have LowID."   # LowID 登录提示
messageLogin: "Welcome to eNode!" # 普通登录提示

servers: []                  # OP_SERVERLIST 中通告的其他服务器（不含本机）；默认为空
  # - ip: "192.0.2.10"
  #   port: 4661

noAssert: false              # 兼容历史行为的断言开关（默认关闭）
logLevel: "debug"            # 日志级别：debug|info|warn|error
logFile: "logs/enode.log"    # 日志文件路径

supportCrypt: true           # 是否启用协议混淆支持
requestCrypt: true           # 是否请求客户端使用混淆
requireCrypt: true           # 是否强制客户端必须混淆
auxiliarPort: false          # 是否声明额外端口能力
IPinLogin: false             # 登录流程中是否包含 IP 信息

tcp:
  port: 5555                 # TCP 主端口
  portObfuscated: 5565       # TCP 混淆端口（supportCrypt=true 时使用）
  maxConnections: 1000000    # 最大连接数
  connectionTimeout: 2000    # 连接建立阶段超时（毫秒）
  disconnectTimeout: 3600    # 空闲断开超时（秒）
  allowLowIDs: true          # 是否允许 LowID 客户端
  minLowID: 1                # LowID 分配最小值
  maxLowID: 16777215         # LowID 分配最大值

udp:
  port: 5559                 # UDP 主端口（tcp.port + 4）
  portObfuscated: 5567       # UDP 混淆端口；须为 tcp.port + 12 才能完成 crypt-ping（见 docs/server-udp-crypt-ping.md）
  getSources: true           # 允许 UDP 来源查询
  getFiles: true             # 允许 UDP 文件查询
  serverKey: 305419896       # 服务端密钥种子；每个客户端的 UDP 混淆密钥由该种子 + 客户端 IP 派生（见 docs/server-udp-crypt-ping.md）

natTraversal:
  enabled: true              # 是否启用 NAT 穿透服务
  port: 2004                 # NAT 穿透 UDP 端口
  registrationTTLSeconds: 30 # NAT 注册表项有效期（秒）

ipv6:                        # IPv6 双栈；整段省略即为仅 IPv4 行为
  enabled: true              # 接受 IPv6 登录并启用 v6 代码路径（默认 true）
  address: ""                # 显式 IPv6 绑定地址；"" 时由顶层 address 决定
  dynIp6: "auto"             # 对外 IPv6，"auto" 通过 testUrls6 探测，"" 则不通告
  publishSources: true       # 发布 IPv6 源并支持 OP_*_IPV6 操作码
  probeReachability: true    # 发布前先验证客户端 IPv6 可达
  testUrls6:                 # 仅 dynIp6=auto 时使用，取第一个可用 IPv6
    - "https://v6.ident.me"
    - "https://api64.ipify.org"

storage:
  engine: memory             # 存储引擎：memory | mysql | mongodb
  cleanup:                   # 过期清理离线客户端及其源
    enabled: true            # 开启周期性清理
    staleAfterHours: 24      # 离线多久后移除客户端
    intervalMinutes: 60      # 清理扫描的执行间隔
    keepZeroSourceFiles: true # 保留最后一个源离线的文件（默认 true）
    batchSize: 1000          # 每批删除的行数
  mysql:
    host: localhost          # MySQL 主机
    port: 3306               # MySQL 端口
    user: enode              # MySQL 用户
    pass: password           # MySQL 密码
    database: enode          # MySQL 数据库
    connections: 8           # MySQL 连接池上限
    deadlockDelay: 100       # 死锁重试等待（毫秒）
    schemaFile: misc/enode.sql # 首次连接且表缺失时执行的 DDL
    dialect: mariadb         # 全文检索：mariadb（可移植）| mysql（ngram 子串）
  mongodb:
    host: 127.0.0.1          # MongoDB 主机（uri 为空时使用）
    port: 27017              # MongoDB 端口（uri 为空时使用）
    database: enode          # MongoDB 数据库名
    uri: ""                  # MongoDB 连接串；非空时优先
```

`address` 与 `dynIp` 的区别：
- `address` 决定服务端绑定监听在哪个本地地址/网卡。
- `dynIp` 决定向客户端通告的服务器 IP（用于客户端回连与 NAT 相关流程）。

MySQL 示例：

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

MongoDB 示例：

```yaml
storage:
  engine: mongodb
  mongodb:
    uri: mongodb://localhost:27017
    database: enode
```

## 构建与测试

运行所有常规测试：

```bash
go test ./...
```

运行真实数据库集成测试（需要 Docker）：

```bash
ENODE_INTEGRATION=1 go test ./storage -run Dockertest -v
```

该测试会启动临时 MySQL 和 MongoDB 容器，初始化 schema/数据，并验证后端的端到端行为。

## 待办

- 更好的存储/索引方案
- IPv6 支持（[eD2K IPv6 扩展非官方草案](http://piratenpad.de/p/ed2kIPv6)）

## 致谢

- David Xanatos

## 说明

- 原 Node.js 仓库与本仓库分离；当前目录是 Go 实现。
- 若 Docker 不可用，集成测试默认跳过（除非显式开启）。
