#define _CRT_SECURE_NO_WARNINGS

#include "ntddk.h"

#include <iostream>
#include <thread>

#include <windows.h>
#include <psapi.h>

namespace helper {

    DWORD GetPid(const char* exename) {
        NTSTATUS status;
        ULONG bufferSize = 0x10000;
        PVOID buffer = NULL;

        do {
            buffer = realloc(buffer, bufferSize);
            if (!buffer)
                return 0;

            status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);

        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(status)) {
            free(buffer);
            return 0;
        }

        PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

        while (TRUE) {
            if (spi->ImageName.Buffer) {
                int nameLength = spi->ImageName.Length / sizeof(WCHAR);
                char* processName = (char*)malloc(nameLength + 1);

                if (processName) {
                    wcstombs(processName, spi->ImageName.Buffer, nameLength);
                    processName[nameLength] = '\0';

                    if (_stricmp(processName, exename) == 0) {
                        DWORD pid = (DWORD)(ULONG_PTR)spi->ProcessId;
                        free(processName);
                        free(buffer);
                        return pid;
                    }

                    free(processName);
                }
            }

            if (spi->NextEntryOffset == 0)
                break;

            spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
        }

        free(buffer);
        return 0;
    }
}

namespace exploit {
    VOID WINAPI Dtr(_In_ DWORD dwMilliseconds) {
    }
    void __declspec(naked) End() {}

    const auto size = [](){
        return reinterpret_cast<uintptr_t>(&End) - reinterpret_cast<uintptr_t>(&Dtr);
    }();

    bool RelativeJump(HANDLE hProcess, uintptr_t addr, uintptr_t hookAddr, int len) {
        DWORD relativeAddy;

        BYTE* originalBytes = new BYTE[len];
        if (!ReadProcessMemory(hProcess, (LPVOID)addr, originalBytes, len, NULL))
			return false;

        BYTE jump = 0xE9;
        BYTE NOP = 0x90;
        BYTE NOPS[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

        relativeAddy = (hookAddr - addr) - 5;

        if (!WriteProcessMemory(hProcess, (LPVOID)addr, &jump, sizeof(jump), NULL) || !WriteProcessMemory(hProcess, (LPVOID)(addr + 0x1), &relativeAddy, sizeof(relativeAddy), NULL))
            return false;

        if (int newLen = len - 5; newLen > 0)
            WriteProcessMemory(hProcess, (LPVOID)(addr + 0x5), NOPS, newLen, NULL);

        Sleep(1000);

        if (!WriteProcessMemory(hProcess, (LPVOID)addr, originalBytes, len, NULL))
			return false;

        return true;
    }
}

int main() {
    DWORD pid;

    do {
        pid = helper::GetPid("test.exe");
        Sleep(1);
    } while (!pid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("OpenProcess failed with error %d\n", GetLastError());
        return 1;
    }

    uintptr_t addr = (uintptr_t)Sleep;

    printf("Shellcode size: %d\n", exploit::size);
    LPVOID shellAddr = VirtualAllocEx(hProcess, NULL, exploit::size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellAddr) {
		printf("VirtualAllocEx failed with error %d\n", GetLastError());
		return 1;
	}

    if (!WriteProcessMemory(hProcess, shellAddr, exploit::Dtr, exploit::size, NULL)) {
        printf("WriteProcessMemory failed with error %d\n", GetLastError());
		return 1;
    }
    
    if (!exploit::RelativeJump(hProcess, addr, (uintptr_t)shellAddr, exploit::size)) {
        printf("Relative jump failed with error %d\n", GetLastError());
		return 1;
	}

    printf("Hooked successfully\n");

    CloseHandle(hProcess);

    return 0;
}
