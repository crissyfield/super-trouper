# super-trouper

`super-trouper` is an MCP server for the [Frida](https://frida.re/) reverse engineering toolkit.

## Status

The `attach` command keeps a Frida device manager for its lifetime and connects by address or to a USB device. The
`mcp` command runs an MCP server over stdio that exposes the Frida bindings as tools. Device connections, sessions,
and scripts are managed through the tools themselves and referenced by handles.

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

### Attach

```sh
export FRIDA_DEVKIT="$PWD/etc/frida-core-devkit"
export SUPER_TROUPER_FRIDA_ADDRESS="iphone.local:27042"
export SUPER_TROUPER_FRIDA_PID="1234"
make run-attach
```

`SUPER_TROUPER_FRIDA_ADDRESS` can also be configured as `frida.address` in `config.yaml` or passed as
`--frida.address host:port`. To connect over USB instead, set `SUPER_TROUPER_FRIDA_USB=true`, configure
`frida.usb: true`, or pass `--frida.usb`; it connects to the first USB device Frida reports. The address and USB
options cannot be used together. `SUPER_TROUPER_FRIDA_PID` identifies the process to attach; the server loads a
persistent JavaScript evaluator and logs its result.

`make run` remains an alias for `make run-attach`.

### MCP

Run the MCP server over stdio:

```sh
export FRIDA_DEVKIT="$PWD/etc/frida-core-devkit"
make run-mcp
```
