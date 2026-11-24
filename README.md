<p align="center"><img src="assets/logo.png" width="320"></p>

# basalt

An experimental Xbox Series S research emulator written in C++23.

basalt is a from-scratch x86-64 interpreter plus just enough of the console's
user-mode environment (PE32+ loader, GDK runtime stubs, a cooperative thread
scheduler, fake COM/D3D12 objects) to boot a title executable and watch how far
it gets. It is a learning and reverse-engineering project, not a playable
emulator.

## Status

| area | state |
| --- | --- |
| x86-64 integer + SSE interpreter | working, unit-tested |
| PE32+ loader, imports, TLS | working |
| GDK / Win32 / CRT stubs | partial, logged when missing |
| thread scheduler, events, waits | working |
| D3D12 / GPU | fake COM objects, no rendering yet |
| audio, input, network | not started |

## Build

Requires clang (C++23), make and GoogleTest.

```bash
./build.sh                                # builds build/basalt
make tests && ./build/basalt_tests        # unit tests
```

Or build and test on a remote Linux host:

```bash
BASALT_HOST=user@host ./remote_build.sh
```

## Usage

```bash
basalt --launch <title_dir> [--max-insns N] [--trace-from exe+off|0xVA]
basalt <boot_image>
```

Set `BASALT_PROBE=rva1,rva2` to log registers each time execution reaches
those offsets in the main executable.

## Layout

```
src/cpu      decoder, executor, interpreter loop
src/memory   memory map, MMU
src/kernel   PE loader, DLL runner, GDK stubs, scheduler
src/gpu      command processor, ring buffer
src/hal      interrupt controller, timer
src/bus      PCIe bus model
tests        GoogleTest suites
tools        helper scripts
```

## Legal

basalt contains no Microsoft code, firmware, keys or game data, and does not
decrypt anything. You need your own legally obtained, already-readable files.
Xbox is a trademark of Microsoft; this project is not affiliated with it.

## License

MIT
