# AGENTS.md

## Commands

- Format changed Go files with `gofmt -w <files>`.
- `go vet ./...` is the fast verification; `golangci-lint run ./...` is the full lint check (`.golangci.yml` v2).
- `go build ./...` compiles every package.
- NEVER add test files to this project.
- Typical post-edit flow: `gofmt -w <files>`, then `go vet ./...` (or `golangci-lint run ./...` for full lint), then `go build ./...`.

## Structure

- `main.go` owns `CmdRoot`, Viper setup, slog setup, signal-aware execution, and final error logging/exiting. Register commands with `CmdRoot.AddCommand`.
- Cobra commands in `cmd/` use the command context for work that can block. Do not call `os.Exit` outside `main`.
- `cmd/serve.go` defines the MCP server command. Its run function is intentionally empty until server behavior is implemented.

## Configuration

- Viper reads CLI flags, `SUPER_TROUPER_` environment variables, then config files named `config` (for example, `config.yaml`) in `/etc/super-trouper`, `~/.config/super-trouper`, and the working directory. Dots and hyphens become underscores, for example `SUPER_TROUPER_LOGGING_LEVEL`.
- Logging flags are `logging.level` and `logging.json`.

## Conventions

- Use `log/slog` for user-facing output and wrap returned errors with `%w`.
- Project-owned prose and identifier segments use uppercase initialisms: `URL`, `HTTP`, `JSON`, `MCP`, `API`, and `CLI`. Keep required lowercase external names and config keys unchanged, such as `net/url` and `logging.json`.
- Enclose every comparison operand in an `if` condition joined by `&&` or `||` in parentheses. Do not parenthesize boolean predicates or negated boolean predicates that do not use `==` or `!=`.
