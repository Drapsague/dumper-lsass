#!/bin/bash
# x86_64-w64-mingw32-g++ -O3 -static -w -fno-stack-protector -DNDEBUG main.cpp -o dump.exe -mconsole
# x86_64-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ -fpermissive -ldbghelp -w -fno-stack-protector  main.cpp -o dump.exe -mconsole 
# x86_64-w64-mingw32-g++ -O2 -Wall main.cpp -o dump.exe -ldbghelp -lpsapi
# x86_64-w64-mingw32-g++ main.cpp syscalls.asm -o dump.exe -O2 -s -static-libstdc++ -static-libgcc -ldbghelp -lntdll
yasm -f win64 syscalls.asm -o syscalls.o
x86_64-w64-mingw32-g++ main.cpp syscalls.o -o dump.exe -O2 -s -static-libstdc++ -static-libgcc -ldbghelp -lntdll
cp dump.exe /home/vedlam/maldev

