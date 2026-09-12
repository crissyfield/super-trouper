<p align="center">
  <img src="etc/images/logo.png" width="320" alt="super-trouper logo">
</p>


# Super Trouper

An MCP server for the [Frida](https://frida.re/) reverse engineering toolkit.

**Super Trouper** runs an MCP server over `STDIO` that exposes Frida capabilities as tools for coding agents. It
can connect to local, USB, and remote devices; inspect applications and processes; manage process sessions; and
load, evaluate, and exchange messages with JavaScript instrumentation scripts. Device connections, sessions, and
scripts are managed through the tools themselves and referenced by opaque handles.


## Install

### Homebrew

Install the macOS release through the project’s Homebrew tap:

```sh
brew install --cask crissyfield/tap/super-trouper
```


### Release Binary

Download a binary for your platform from the [Releases
page](https://github.com/crissyfield/super-trouper/releases).


### From Source

Install a [Frida Core DevKit](https://github.com/frida/frida/releases) matching your build host first. Then
build and install **Super Trouper** with the following commands:

```sh
# Set flags if the Frida devkit is not in a standard location
export CGO_CFLAGS="-I..path/to/frida-core-devkit/include"
export CGO_LDFLAGS="-L..path/to/frida-core-devkit/lib"

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
