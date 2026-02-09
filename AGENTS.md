# Repository Guidelines

## Project Structure & Module Organization
- `cmd/enode/`: application entrypoint (`main.go`) and runtime wiring.
- `config/`: YAML config loader and config tests.
- `ed2k/`: core protocol logic (packet/buffer/crypto/client/server operations).
- `storage/`: storage engines (`memory`, `mysql`, `mongodb`), factory, and integration tests.
- `enode.config.yaml`: default local runtime configuration.
- `README.md` / `README.zh-CN.md`: user-facing documentation.

Keep new code in the nearest domain package (`ed2k` vs `storage`) and avoid cross-package cycles.

## Build, Test, and Development Commands
- `go test ./...`: run all unit tests.
- `go run ./cmd/enode -config enode.config.yaml`: start the server locally.
- `ENODE_INTEGRATION=1 go test ./storage -run Dockertest -v`: run real MySQL/Mongo integration tests (Docker required).
- `gofmt -w ./...` is not valid; format by package/file, e.g. `gofmt -w ed2k/*.go storage/*.go`.

Use integration tests only when changing DB behavior or schema-sensitive logic.

## Coding Style & Naming Conventions
- Follow idiomatic Go and keep code `gofmt`-formatted.
- Package names: short, lowercase (`ed2k`, `storage`, `config`).
- Exported identifiers: `CamelCase`; unexported: `camelCase`.
- Tests: one behavior per test where practical; prefer table tests for parsing/validation branches.
- Config keys should remain backward-compatible with `enode.config.yaml`.

## Testing Guidelines
- Framework: Go standard testing package (`testing`).
- Test files end with `_test.go`; test functions use `TestXxx`.
- Add unit tests with every logic change.
- For DB engines:
  - unit tests for config/constructor/edge paths;
  - dockertest integration coverage for real CRUD/query flows.

## Commit & Pull Request Guidelines
- Current history is minimal (`init commit`); use clear, imperative commit messages.
- Recommended format: `area: change` (example: `storage: fix mysql source query ordering`).
- PRs should include:
  - purpose and scope,
  - key files changed,
  - test evidence (`go test ./...`, integration commands if relevant),
  - config or migration notes when behavior changes.

## Security & Configuration Tips
- Do not commit real DB credentials; keep `enode.config.yaml` values non-production.
- Prefer environment-specific config files outside version control for deployment.
