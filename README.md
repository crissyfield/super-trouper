# super-trouper

`super-trouper` is an MCP server for the [Frida](https://frida.re/) reverse engineering toolkit.

## Status

The `serve` command connects to a remote Frida server. MCP tools are not implemented yet.

## Install

```sh
export FRIDA_DEVKIT="$PWD/etc/frida-core-devkit"
make install
```

## Build

Building requires a Frida Core devkit matching the build host. Set `FRIDA_DEVKIT` to the directory containing
`include/frida-core.h` and `lib/libfrida-core.a`:

```sh
export FRIDA_DEVKIT="$PWD/etc/frida-core-devkit"
make build
```

## Usage

```sh
export FRIDA_DEVKIT="$PWD/etc/frida-core-devkit"
export SUPER_TROUPER_FRIDA_ADDRESS="iphone.local:27042"
export SUPER_TROUPER_FRIDA_PID="1234"
make run
```

`SUPER_TROUPER_FRIDA_ADDRESS` can also be configured as `frida.address` in `config.yaml` or passed as
`--frida.address host:port`. `SUPER_TROUPER_FRIDA_PID` identifies the process to attach; the server loads a
persistent JavaScript evaluator, evaluates `1+1`, and logs its result.
