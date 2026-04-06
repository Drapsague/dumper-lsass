#pragma once
#include <windows.h>

typedef BOOL(WINAPI* OpenProcessToken_t)(HANDLE ProcessHandle, DWORD DesiredAccess,
                                         PHANDLE TokenHandle);
typedef BOOL(WINAPI* LookupPrivilegeValueA_t)(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
typedef BOOL(WINAPI* AdjustTokenPrivileges_t)(HANDLE TokenHandle, BOOL DisableAllPrivileges,
                                              PTOKEN_PRIVILEGES NewState, DWORD BufferLength,
                                              PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
typedef BOOL(WINAPI* MiniDumpWriteDump_t)(HANDLE hProcess, DWORD ProcessId, HANDLE hFile,
                                          DWORD DumpType, PVOID ExceptionParam,
                                          PVOID UserStreamParam, PVOID CallbackParam);

typedef HANDLE(WINAPI* OpenProcess_t)(DWORD dwDesiredAccess, BOOL bInheritHandle,
                                      DWORD dwProcessId);
