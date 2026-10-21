# AGENTS.md

## Build and verification

- Use Go 1.27.0 as specified in `go.mod` and CI; `Evaluator.Evaluate[T]` uses generic methods. Go tooling also needs CGO and a host-compatible Frida Core DevKit; releases currently use 17.23.3.
- For an `include/` + `lib/` devkit layout, export the following before running Go or lint commands (the local `etc/frida-core-devkit/` is untracked; do not assume it exists):

  ```sh
  export CGO_ENABLED=1
  export CGO_CFLAGS="-I/path/to/frida-core-devkit/include"
  export CGO_LDFLAGS="-L/path/to/frida-core-devkit/lib"
  ```

- Raw Frida release archives put `frida-core.h` and `libfrida-core.a` at their root; point both flags there unless you rearrange them as CI does.
- Post-edit flow: `gofmt -w <changed Go files>`, then `go vet ./...`, then `go build ./...`. Full lint: `golangci-lint run ./...` (v2 config). Run/install with `go run .` / `go install .` using the same CGO environment.
- NEVER add test files to this project. On SIP-enabled macOS without root, injection can time out with "Timeout was reached"; `session_attach` and evaluator end-to-end checks need privileges. Device/application/process listing, spawning, and killing work without them.

## Architecture and lifecycle

- `main.go` wires the Frida manager and CodeShare client into `mcpserver.New(manager, codeShare, version)`, which returns a server and an error (startup loads persisted Pattern projects). Register new tool groups in `internal/mcpserver/server.go:New` and document tools in `README.md`.
- Stdout is exclusively MCP stdio transport; send logs through `slog` to stderr. `main` owns signal handling and process exit; `context.Canceled` is a clean shutdown. Cleanup uses fresh 10-second contexts and closes the MCP server before the Frida manager.
- MCP devices, sessions, scripts, and Pattern projects use opaque handles. `MCPServer.mu` guards state maps; helpers suffixed `Locked` require the caller to hold it. `patternModule` requires keeping that lock for the entire use of the returned native module.
- `Manager.Close` does not close active devices. Release scripts/evaluators before sessions and sessions before devices; close cached Pattern modules before the manager. CGO helpers `newCancellable` and `consumeGError` live in `internal/frida/utils.go`; library init/deinit is manager-refcounted in `library.go`.
- The persistent per-session evaluator is embedded from `internal/frida/assets/evaluator.ts` and bundled through `Manager.BuildScript`; update Go and TypeScript message formats together. Compilation and npm installation use Frida's native APIs, not a host Node/npm toolchain.
- Packages, temporary script builds, and persisted `patterns/<handle>/` projects share `os.UserCacheDir()/super-trouper/frida/<Frida version>/`. Use `WorkspaceRoot`, not a hard-coded `~/.cache` path (macOS differs). Package writes and compiler reads coordinate through `Manager.workspaceMu`.
- Pattern compilation uses the shared workspace as project root for package imports and the target's `Process.platform`/`Process.arch` for ABI layout. Modules are cached by target ABI and preprocessor defines. `pattern_describe`/`pattern_decode` intentionally return `any`: current `jsonschema-go` cannot generate schemas for their recursive output types.

## Configuration

- Logging flags/config keys are `log-level` (`-l`) and `log-as-json` (`-j`); environment equivalents are `SUPER_TROUPER_LOG_LEVEL` and `SUPER_TROUPER_LOG_AS_JSON`. Explicit flags override environment, then config. Viper searches for `config` in `/etc/super-trouper`, `~/.config/super-trouper`, then the working directory; it reads the first matching file.
- Device selection is through `device_connect`, not startup flags.

## Release packaging

- `.github/workflows/release.yml` runs on `v*` tags. macOS arm64 must build natively with Apple's linker; `.goreleaser.yaml` handles the remaining targets in a cross-compilation container. A plain `GOOS`/`GOARCH` change is insufficient for CGO cross-builds.
- Update both `FRIDA_VERSION` entries in the release workflow and the README when changing DevKit versions. `etc/npm/` is a binary launcher/publishing layer, not an application workspace; placeholder package versions are filled during publishing. Packaging dry-run: `bash etc/npm/publish.sh VERSION ASSETS_DIRECTORY --dry-run` (Bash 4+; requires release archives and `checksums.txt`).

## Conventions

- Wrap returned errors with `%w`; `.golangci.yml` enables `errorlint` and `revive`'s deep-exit rule.
- Project-owned prose and identifier segments use uppercase initialisms: `URL`, `HTTP`, `JSON`, `MCP`, `API`, and `CLI`. Keep required lowercase external names and config keys unchanged, such as `net/url` and `logging.json`.
- Enclose every comparison operand in an `if` condition joined by `&&` or `||` in parentheses. Do not parenthesize boolean predicates or negated boolean predicates that do not use `==` or `!=`.
