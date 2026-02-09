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
- LowID 回调
- NAT 穿透服务端（`OP_VC_NAT_HEADER`、`OP_NAT_REGISTER`、`OP_NAT_SYNC2`）
- 支持大于 4 GiB 的文件
- 易于扩展多种存储引擎

## 配置

运行配置使用 YAML：

- `enode.config.yaml`

支持通过参数指定配置路径：

```bash
go run ./cmd/enode -config enode.config.yaml
```

关键配置项：

```yaml
storage:
  engine: memory   # memory | mysql | mongodb

natTraversal:
  enabled: true
  port: 2004
  registrationTTLSeconds: 600
```

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

- `OP_FOUNDSOURCES_OBFU`
- 每 5 分钟向已连接客户端发送 `OP_SERVERSTATUS`
- 更好的存储/索引方案
- IPv6 支持（[eD2K IPv6 扩展非官方草案](http://piratenpad.de/p/ed2kIPv6)）

## 致谢

- David Xanatos

## 说明

- 原 Node.js 仓库与本仓库分离；当前目录是 Go 实现。
- 若 Docker 不可用，集成测试默认跳过（除非显式开启）。
