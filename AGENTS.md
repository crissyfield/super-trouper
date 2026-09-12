# AGENTS.md

## Commands

- The project links `frida-core` via CGO, so Go tooling requires a Frida Core devkit matching the build host. If it is not installed in a standard location, set `CGO_ENABLED=1`, `CGO_CFLAGS="-I/path/to/frida-core-devkit/include"`, and `CGO_LDFLAGS="-L/path/to/frida-core-devkit/lib"`.
- Use `go vet ./...`, `go build ./...`, `go install .`, and `go run .` directly; the CGO environment must be set for each command when the devkit is in a non-standard location.
- Format changed Go files with `gofmt -w <files>`.
- `go vet ./...` is the fast verification; `golangci-lint run ./...` is the full lint check (`.golangci.yml` v2).
- NEVER add test files to this project.
- On a SIP-enabled macOS host without root, process injection fails with a frida-core timeout ("Timeout was reached"), so end-to-end testing of the MCP `attach` tool and evaluator needs privileges; device listing, application/process listing, spawning, and killing work without them.
- Typical post-edit flow: `gofmt -w <files>`, then `go vet ./...` (or `golangci-lint run ./...` for full lint), then `go build ./...`.

## Structure

- `main.go` defines `cmdMain`, configures Viper and slog, creates a Frida manager, builds an `mcpserver.MCPServer` via `mcpserver.New`, and runs it over stdio until the command context is cancelled. It treats `context.Canceled` as a clean shutdown, closes resources with 10-second timeout contexts, and owns signal-aware execution and final error logging/exiting. Do not call `os.Exit` outside `main`.
- `internal/mcpserver/` implements the MCP server with `github.com/modelcontextprotocol/go-sdk/mcp`. `MCPServer` (in `server.go`) holds the `*mcp.Server`, the injected `*frida.Manager`, and mutex-guarded state maps; `New(manager, version)` registers all tools, `Run(ctx)` runs the stdio transport, and `Close(ctx)` closes all scripts, sessions, and devices created through tools. Tool handlers are methods grouped by domain in `devices.go`, `applications.go`, `processes.go`, `sessions.go`, and `scripts.go`. Devices, sessions, and scripts are referenced by opaque UUID handles; handlers synchronize state map access with `mu`.
- `internal/frida/` is a CGO wrapper over frida-core exposing `Manager`, `Device`, `Session`, `Evaluator`, `Script`, `Process`, and `Application`. It embeds the evaluator script from `assets/evaluator.js`, provides GIO-cancellable helpers in `tools.go`, and performs refcounted library init in `library.go`.

## Configuration

- Viper reads CLI flags, `SUPER_TROUPER_` environment variables, then config files named `config` (for example, `config.yaml`) in `/etc/super-trouper`, `~/.config/super-trouper`, and the working directory. Dots and hyphens become underscores, for example `SUPER_TROUPER_LOGGING_LEVEL`.
- Logging flags are `logging.level` and `logging.json`.
- `cmdMain` adds no MCP-specific flags. Devices are connected dynamically through the `device_connect` tool (by device ID, remote address, or type), and tools referencing devices, sessions, or scripts take opaque handles.

## Conventions

- Use `log/slog` for user-facing output and wrap returned errors with `%w`.
- Project-owned prose and identifier segments use uppercase initialisms: `URL`, `HTTP`, `JSON`, `MCP`, `API`, and `CLI`. Keep required lowercase external names and config keys unchanged, such as `net/url` and `logging.json`.
- Enclose every comparison operand in an `if` condition joined by `&&` or `||` in parentheses. Do not parenthesize boolean predicates or negated boolean predicates that do not use `==` or `!=`.
