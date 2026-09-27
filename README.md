<p align="center">
  <img src="https://crissyfield.github.io/assets/super-trouper-logo.png" width="320" alt="super-trouper logo">
</p>


# Super Trouper

An MCP server for the [Frida](https://frida.re/) reverse engineering toolkit.

**Super Trouper** runs an MCP server over `STDIO` that exposes Frida capabilities as tools for coding agents. It
can connect to local, USB, and remote devices; inspect applications and processes; manage process sessions; and
load, evaluate, and exchange messages with JavaScript instrumentation scripts. It can also search [Frida
CodeShare](https://codeshare.frida.re) to discover community scripts and fetch them for use with the scripting
tools. Device connections, sessions, and scripts are managed through the tools themselves and referenced by
opaque handles.

<img width="1512" height="950" alt="super-trouper" src="https://crissyfield.github.io/assets/super-trouper-demo.webp" />


## Features

- **Single Go binary** — no Python, Node, or Frida CLI tooling required on your host
- **Powered by Frida 17.x** — statically linked against Frida Core DevKit v17.19.0
- **Full device support** — list and connect to local, USB, and remote devices, attach to apps and processes
- **TypeScript and JavaScript instrumentation** — create and load Frida scripts, evaluate directly in a target
- **Frida CodeShare integration** — search, browse, and fetch the CodeShare catalog of community scripts
- **Runs anywhere** — prebuilt binaries for macOS and Linux, install via Docker, Homebrew, or npm


## Install

### Homebrew

Install the macOS release through the project’s Homebrew tap:

```sh
brew install --cask crissyfield/tap/super-trouper
```


### npm

Install the launcher package through npm. It pulls in the platform-specific binary via optional dependencies:

```sh
npm install -g @crissyfield/super-trouper
```


### Release Binary

Download a binary for your platform from the [Releases
page](https://github.com/crissyfield/super-trouper/releases).


### From Source

Install a [Frida Core DevKit](https://github.com/frida/frida/releases) matching your build host first. Then
build and install **Super Trouper** with the following commands:

```sh
# Set flags if the Frida devkit is not in a standard location
export CGO_CFLAGS="-I/path/to/frida-core-devkit/include"
export CGO_LDFLAGS="-L/path/to/frida-core-devkit/lib"

# Build and install
export CGO_ENABLED=1
go install github.com/crissyfield/super-trouper@latest
```


## Usage

Use the MCP server in your coding agent. [Claude Code](https://docs.anthropic.com/en/docs/claude-code/mcp) is
the example below, but configuration is similar in [Codex](https://developers.openai.com/codex/mcp),
[OpenCode](https://opencode.ai/docs/mcp-servers/), [Pi](https://pi.dev/packages/pi-mcp-adapter),
[Crush](https://charmbracelet-crush.mintlify.app/configuration/mcp), and others.


### Using the Binary

If the **Super Trouper** binary is not in your `PATH`, specify the full path in your MCP server configuration.

```json
{
  "mcpServers": {
    "super-trouper": {
      "command": "super-trouper"
    }
  }
}
```


### Using npx

npm users can run **Super Trouper** directly through `npx` without a global installation:

```json
{
  "mcpServers": {
    "super-trouper": {
      "command": "npx",
      "args": ["-y", "@crissyfield/super-trouper"]
    }
  }
}
```


### Using Docker

Docker is a convenient way to run **Super Trouper** without installing it on your host.

```json
{
  "mcpServers": {
    "super-trouper": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/crissyfield/super-trouper"]
    }
  }
}
```


## MCP Tools

Super Trouper exposes the following MCP tools:

| Tool                  | Description                                                                                                                                                                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `app_list`            | Lists the applications installed on a Frida device.                                                                                                                                                                            |
| `app_find`            | Finds an application on a Frida device by identifier or name.                                                                                                                                                                  |
| `app_frontmost`       | Returns the frontmost application on a Frida device.                                                                                                                                                                           |
| `codeshare_search`    | Searches [Frida CodeShare](https://codeshare.frida.re) for projects matching the given query.                                                                                                                                  |
| `codeshare_popular`   | Lists the most popular projects on [Frida CodeShare](https://codeshare.frida.re).                                                                                                                                              |
| `codeshare_project`   | Returns a project from [Frida CodeShare](https://codeshare.frida.re), including its JavaScript source, which can be run with the other scripting tools.                                                                        |
| `device_list`         | Lists the Frida devices detected by the host.                                                                                                                                                                                  |
| `device_connect`      | Connects to a Frida device by ID reported by `device_list`, by a remote Frida server address, or by type. Returns a device handle used by the other device tools; reconnecting to the same device returns the existing handle. |
| `device_disconnect`   | Disconnects from a Frida device. Fails while the device still has attached sessions.                                                                                                                                           |
| `device_params`       | Returns the parameters of a Frida device.                                                                                                                                                                                      |
| `device_spawn`        | Spawns a process on a Frida device in a suspended state. Use `device_resume` to start it.                                                                                                                                      |
| `device_resume`       | Resumes a suspended process on a Frida device.                                                                                                                                                                                 |
| `device_kill`         | Kills a process on a Frida device.                                                                                                                                                                                             |
| `memory_read`         | Reads up to 4096 bytes of memory in an attached process and returns it as hex, base64, UTF-8, or a NUL-terminated C string. Fails if any byte of the range cannot be read.                                                     |
| `memory_write`        | Writes up to 4096 bytes of memory in an attached process as hex (default) or base64, selected with the encoding parameter. Fails if memory cannot be written; patching code is out of scope.                                   |
| `module_list`         | Lists the modules loaded in an attached process. Results can be matched by name or path and paginated.                                                                                                                         |
| `process_list`        | Lists the processes running on a Frida device.                                                                                                                                                                                 |
| `script_create`       | Creates a Frida script with TypeScript source in an attached session. The script is created unloaded; use `script_load` to load it.                                                                                            |
| `script_load`         | Loads a Frida script into its target process.                                                                                                                                                                                  |
| `script_unload`       | Unloads a Frida script from its target process.                                                                                                                                                                                |
| `script_close`        | Unloads a Frida script if loaded and releases its resources.                                                                                                                                                                   |
| `script_post`         | Posts a JSON message to a Frida script.                                                                                                                                                                                        |
| `script_messages`     | Returns messages sent by a Frida script. Messages are buffered (up to 256) and should be drained regularly.                                                                                                                    |
| `script_bridge_list`  | Returns the language bridges that can be exposed as globals in scripts created with `script_create`.                                                                                                                           |
| `session_attach`      | Attaches to a process on a Frida device by PID or name. Returns a session handle used by the session tools.                                                                                                                    |
| `session_detach`      | Detaches from a process, closing all of its scripts and its session.                                                                                                                                                           |
| `session_eval`        | Evaluates a JavaScript statement in an attached process and returns its JSON result. The first call sets up a persistent evaluator in the session.                                                                             |
| `frida_version`       | Returns the version of the linked Frida Core library.                                                                                                                                                                          |
| `frida_documentation` | Returns documentation links for the Frida JavaScript API.                                                                                                                                                                      |
| `thread_list`         | Lists the threads running in an attached process with their ID, state, and program counter.                                                                                                                                    |
