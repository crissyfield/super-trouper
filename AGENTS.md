# AGENTS.md

## Commands

- The project links `frida-core` via CGO, so Go tooling requires a Frida Core devkit: set `FRIDA_DEVKIT` to a directory containing `include/frida-core.h` and `lib/libfrida-core.a`, for example `export FRIDA_DEVKIT="$PWD/etc/frida-core-devkit"`. The current Frida C header is `etc/frida-core-devkit/include/frida-core.h`.
- `make vet`, `make build`, `make install`, and `make run` wrap the Go tooling with the required devkit flags; `make run` executes `go run . serve`.
- Format changed Go files with `gofmt -w <files>`.
- `make vet` is the fast verification; `golangci-lint run ./...` is the full lint check (`.golangci.yml` v2).
- NEVER add test files to this project.
- Typical post-edit flow: `gofmt -w <files>`, then `make vet` (or `golangci-lint run ./...` for full lint), then `make build`.

## Structure

- `main.go` owns `CmdRoot`, Viper setup, slog setup, signal-aware execution, and final error logging/exiting. Register commands with `CmdRoot.AddCommand`.
- Cobra commands in `cmd/` use the command context for work that can block. Do not call `os.Exit` outside `main`.
- `cmd/serve.go` defines the MCP server command. It connects to a Frida device (`--frida.address` or `--frida.usb`, mutually exclusive), lists applications, attaches to the process given by `--frida.pid`, creates the persistent JavaScript evaluator, and evaluates and logs JavaScript. MCP tools are not implemented yet.
- `internal/frida/` is a CGO wrapper over frida-core exposing `Manager`, `Device`, `Session`, `Evaluator`, `Script`, `Process`, and `Application`. It embeds the evaluator script from `assets/evaluator.js`, provides GIO-cancellable helpers in `tools.go`, and performs refcounted library init in `library.go`.

## Configuration

- Viper reads CLI flags, `SUPER_TROUPER_` environment variables, then config files named `config` (for example, `config.yaml`) in `/etc/super-trouper`, `~/.config/super-trouper`, and the working directory. Dots and hyphens become underscores, for example `SUPER_TROUPER_LOGGING_LEVEL`.
- Logging flags are `logging.level` and `logging.json`.
- The `serve` command adds `frida.address`, `frida.usb`, and `frida.pid` (environment variables `SUPER_TROUPER_FRIDA_ADDRESS`, `SUPER_TROUPER_FRIDA_USB`, and `SUPER_TROUPER_FRIDA_PID`). Address and USB options cannot be used together.

## Conventions

- Use `log/slog` for user-facing output and wrap returned errors with `%w`.
- Project-owned prose and identifier segments use uppercase initialisms: `URL`, `HTTP`, `JSON`, `MCP`, `API`, and `CLI`. Keep required lowercase external names and config keys unchanged, such as `net/url` and `logging.json`.
- Enclose every comparison operand in an `if` condition joined by `&&` or `||` in parentheses. Do not parenthesize boolean predicates or negated boolean predicates that do not use `==` or `!=`.
