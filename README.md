# super-trouper

`super-trouper` is an MCP server for the [Frida](https://frida.re/) reverse engineering toolkit.

## Status

The `serve` command keeps a Frida device manager for its lifetime and connects by address or to a USB device. MCP
tools are not implemented yet.

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
`--frida.address host:port`. To connect over USB instead, set `SUPER_TROUPER_FRIDA_USB=true`, configure
`frida.usb: true`, or pass `--frida.usb`; it connects to the first USB device Frida reports. The address and USB
options cannot be used together. `SUPER_TROUPER_FRIDA_PID` identifies the process to attach; the server loads a
persistent JavaScript evaluator and logs its result.
