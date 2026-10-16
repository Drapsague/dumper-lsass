#!/bin/bash
# Cross-compile the dumper with mingw-w64.
# Usage: ./compile.sh [output-name]
set -e

OUT="${1:-$(mktemp -u HJK_XXXXXXXX).exe}"

echo "Compiling $OUT"
x86_64-w64-mingw32-g++ main.c -o "$OUT" \
  -O1 \
  -fno-stack-protector \
  -fvisibility=hidden \
  -Wl,--subsystem,console \
  -Wl,-emain \
  -lshlwapi -ldbghelp -lkernel32 -lntdll

echo "[+] Built $OUT"