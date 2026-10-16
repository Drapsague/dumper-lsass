# Dumper_LSASS

A small C tool for Windows that locates the **LSASS** process, enables
`SeDebugPrivilege`, and writes a memory dump of it to a `.dmp` file — built for
red team operations and security research where credentials must be collected
from a compromised host.

> **Authorized use only.** This tool is intended for offensive security
> professionals operating within the scope of a written engagement, and for
> defenders/researchers who want to understand these techniques. Running it on
> systems you do not own or lack explicit permission to test is illegal.

## How it works

The implementation avoids statically imported, high-value APIs so that simple
import-table detections have nothing to flag:

1. **Privilege escalation** — `OpenProcessToken`, `LookupPrivilegeValueA` and
   `AdjustTokenPrivileges` are resolved at runtime by walking the export table
   of `advapi32.dll` and matching a custom hash of each function name. They are
   used to enable `SeDebugPrivilege` on the current process.
2. **Target discovery** — the LSASS PID is found via
   `CreateToolhelp32Snapshot` / `Process32Next`, matching the process name
   case-insensitively.
3. **Dump** — a handle to LSASS is opened with
   `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, and the dump is
   produced by `MiniDumpWriteDump`, resolved by hash from `dbgcore.dll`, with
   dump type `MiniDumpWithFullMemory` (`0x00000002`).
4. The dump is written to a `.dmp` file in the current working directory.

Tested against Defender, Avast and Avira, with PPL (Protected Process Light)
disabled on the target.

## Requirements

- Target: Windows x64, running as a local administrator (for `SeDebugPrivilege`), PPL disabled
- Build host: `x86_64-w64-mingw32-g++` (mingw-w64 cross-compiler), bash

## Build

```bash
./compile.sh            # builds an exe with a random name
./compile.sh mydump.exe # builds with a chosen name
```

## Usage

Run the built executable from an elevated shell on the target. On success it
prints the resolved functions, the LSASS PID, and writes the `.dmp` file:

```
[+] SeDebugPrivilege enabled !!
  PID: 592
  Trying to dump the process memory...
[+] The dump succeeded !!!!
```

The dump can then be exfiltrated and parsed offline (e.g. with
[Mimikatz](https://github.com/gentilkiwi/mimikatz),
[pypykatz](https://github.com/skelsec/pypykatz) or
[MiniDump Explorer](https://github.com/3xpl01tc0d3r/MiniDump-Explorer)) to
extract credentials.

## Auxiliary scripts (`script/`)

Helper utilities for packaging and obfuscating payloads during delivery:

| Script | Purpose |
| --- | --- |
| `ConvertToShellcode.py` | Converts a DLL into position-independent shellcode (shellcode-based [ShellcodeRDI](https://github.com/boku7/ShellcodeRDI)) |
| `ShellcodeRDI.py` | The underlying RDI (reflective DLL injection) conversion library |
| `xor.py` | XOR-encodes a file with a repeating key and prints it as C bytes |
| `hex_to_b64.py` | Converts a C-style hex byte array to Base64 |

## Roadmap

- [ ] Bypass PPL (Protected Process Light) so PPL-enabled LSASS can be dumped
- [ ] API hashing for token privilege API calls (partially implemented)
- [ ] Remove console output / add silent mode

## Repository layout

```
├── main.c        # tool entry point: hashing, privilege, discovery, dump
├── main.h        # function-pointer typedefs for dynamically resolved APIs
├── compile.sh    # mingw-w64 cross-compilation script
└── script/       # payload packaging helpers (RDI, XOR, hex→base64)
```