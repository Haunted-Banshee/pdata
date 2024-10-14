#include <Windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "Stuff.h"
#pragma comment(lib, "dbghelp.lib")

DWORD_PTR GetModuleBaseAddress(HANDLE hProcess, DWORD_PTR address)
{
    HMODULE hModules[1024];
    DWORD cbNeeded;
    DWORD i;

    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            MODULEINFO moduleInfo;

            if (GetModuleInformation(hProcess, hModules[i], &moduleInfo, sizeof(moduleInfo)))
            {
                DWORD_PTR moduleBase = (DWORD_PTR)moduleInfo.lpBaseOfDll;
                DWORD_PTR moduleSize = (DWORD_PTR)moduleInfo.SizeOfImage;

                if (address >= moduleBase && address < (moduleBase + moduleSize))
                {
                    return moduleBase;
                }
            }
        }
    }

    return 0;
}

BOOLEAN GetStartAndEndFromPdata(LPCSTR FullExeName, PVOID ModuleBase, PVOID* StartAddressBegin, PVOID* StartAddressEnd, PVOID func)
{
    HANDLE hFile = CreateFileA(FullExeName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open the file, Error: %lu\n", GetLastError());
        return NULL;
    }

    DWORD FileSize = GetFileSize(hFile, NULL);
    PBYTE buffer = (PBYTE)malloc(FileSize);

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, FileSize, &bytesRead, NULL) || bytesRead != FileSize)
    {
        printf("Failed to read the file %s, Error: %lu\n", FullExeName, GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS64)(buffer + Dos->e_lfanew);
    PIMAGE_SECTION_HEADER SecHead = (PIMAGE_SECTION_HEADER)(NTHeaders + 1);

    for (int i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(SecHead[i].Name, ".pdata", 6) == 0)
        {
            PBYTE   PdataSec = buffer + SecHead[i].PointerToRawData;
            DWORD   PdataSize = SecHead[i].SizeOfRawData;

            for (DWORD j = 0; j < PdataSize; j++)
            {
                PRUNTIME_FUNCTION p = (PRUNTIME_FUNCTION)(PdataSec + j);
                PBYTE Start = (PBYTE)ModuleBase + p->BeginAddress;
                PBYTE End = (PBYTE)ModuleBase + p->EndAddress;

                if (func >= Start && func <= End)
                {
                    *StartAddressBegin = Start;
                    *StartAddressEnd = End;
                    free(buffer);
                    CloseHandle(hFile);
                    return 1;
                }

            }
        }
    }

    free(buffer);
    CloseHandle(hFile);
    return 0;
}
BOOLEAN GetTextSectionRange(LPCSTR FullExeName, PVOID ModuleBase, PVOID* StartAddressBegin, PVOID* StartAddressEnd)
{
    HANDLE hFile = CreateFileA(FullExeName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open the file, Error: %lu\n", GetLastError());
        return NULL;
    }

    DWORD FileSize = GetFileSize(hFile, NULL);
    PBYTE buffer = (PBYTE)malloc(FileSize);

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, FileSize, &bytesRead, NULL) || bytesRead != FileSize)
    {
        printf("Failed to read the file %s, Error: %lu\n", FullExeName, GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS64)(buffer + Dos->e_lfanew);
    PIMAGE_SECTION_HEADER SecHead = (PIMAGE_SECTION_HEADER)(NTHeaders + 1);

    for (int i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(SecHead[i].Name, ".text", 5) == 0)
        {
            PBYTE   TextSec = (PBYTE)ModuleBase + SecHead[i].VirtualAddress;
            DWORD   TextSize = SecHead[i].Misc.VirtualSize;

            *StartAddressBegin = TextSec;
            *StartAddressEnd = TextSec + TextSize;
            free(buffer);
            CloseHandle(hFile);
            return TRUE;
        }
    }

    free(buffer);
    CloseHandle(hFile);
    return NULL;
}

VOID GetAllNonSuspendedThreads(PTHREAD* ThreadList)
{
    ULONG uBufferSize = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID pBuffer = NULL;
    BOOL bSuccess = FALSE;
    PTHREAD pThread = NULL;

    PMY_SYSTEM_PROCESS_INFORMATION pProcessInformation = NULL;
    SYSTEM_THREAD_INFORMATION thread_information = { 0 };

    PFN_NtQuerySystemInformation pNtQuerySystemInformation = (PFN_NtQuerySystemInformation)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQuerySystemInformation");

    DWORD ThreadCounter = 0;
    DWORD ProcessCounter = 0;
    do {
        status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, pBuffer, uBufferSize, &uBufferSize);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                if (pBuffer != NULL)
                    VirtualFree(pBuffer, 0, MEM_RELEASE);
                pBuffer = VirtualAlloc(NULL, uBufferSize, MEM_COMMIT, PAGE_READWRITE);
                continue;
            }
            break;
        }
        else {
            pProcessInformation = (MY_SYSTEM_PROCESS_INFORMATION*)pBuffer;
            break;
        }
    } while (1);

    while (pProcessInformation && pProcessInformation->NextEntryOffset) {

        for (ULONG i = 0; i < pProcessInformation->NumberOfThreads; i++) {

            thread_information = pProcessInformation->ThreadInfos[i];


            // Is Thread Suspended?
            if (thread_information.WaitReason != 5) {

                pThread = (PTHREAD)VirtualAlloc(0, sizeof(THREAD), MEM_COMMIT, PAGE_READWRITE);
                if (pThread == NULL)
                    return;

                pThread->wProcessName = pProcessInformation->ImageName.Buffer;
                pThread->dwPid = pProcessInformation->ProcessId;
                pThread->dwTid = (DWORD)thread_information.ClientId.UniqueThread;

                ThreadList[ThreadCounter] = pThread;
                ThreadCounter++;
            }
        }
        ProcessCounter++;

        pProcessInformation = (PMY_SYSTEM_PROCESS_INFORMATION)((LPBYTE)pProcessInformation + pProcessInformation->NextEntryOffset);

    }
    printf("We found %d Processes\n", ProcessCounter);
    printf("We found %d Threads\n", ThreadCounter);


}

VOID SingleProc(DWORD pid, DWORD tid)
{
    pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
    PTHREAD ThreadList[10000] = { 0 };

    GetAllNonSuspendedThreads((PTHREAD*) & ThreadList);

    for (int i = 0; i < 10000; i++)
    {
        PTHREAD p = ThreadList[i];

        if (pid == ThreadList[i]->dwPid && tid == ThreadList[i]->dwTid)
        {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ThreadList[i]->dwPid);

            if (hProcess == NULL)
            {
                return;
            }

            BOOL b = 0;
            IsWow64Process(hProcess, &b);

            // Get full EXE name for the process
            DWORD buffSize = 1024;
            CHAR FullExeName[1024];
            QueryFullProcessImageNameA(hProcess, 0, FullExeName, &buffSize);

            if (b)
            {
                CloseHandle(hProcess);
                return;
            }
            // Step 2: Load the debugging symbols
            if (!SymInitialize(hProcess, NULL, TRUE))
            {
                return;
            }

            // Step 3: Set symbol options
            SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadList[i]->dwTid);
            if (hThread != NULL)
            {
                DWORD64 displacement = 0;
                BYTE symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
                PSYMBOL_INFO pSymbolInfo = (PSYMBOL_INFO)symbolBuffer;
                pSymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
                pSymbolInfo->MaxNameLen = MAX_SYM_NAME;
                MODULEINFO moduleInfo = { 0 };
                LPSTR ModuleBaseName = NULL;
                HMODULE RemoteExeHandle = NULL;
                PVOID UnresolvedModuleBase = NULL;
                BOOL FoundStartAddress = 0;
                PVOID StartAddress = NULL;
                PVOID StartAddressBegin = NULL;
                PVOID StartAddressEnd = NULL;
                PCSTR StartAddressSymbol = NULL;

                // Get a RunTimeFunction for the StartAddress
                DWORD64  temp = NULL;
                PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
                PRUNTIME_FUNCTION rt = RtlLookupFunctionEntry((DWORD64)StartAddress, &temp, pHistoryTable);

                NTSTATUS succ = NtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &StartAddress, sizeof(PVOID), NULL);
                if (succ != 0)
                {
                    SymCleanup(hProcess);
                    CloseHandle(hProcess);
                    CloseHandle(hThread);
                    return;
                }

                printf("======================================\n");

                if (rt == NULL)
                {
                    UnresolvedModuleBase = (PVOID)GetModuleBaseAddress(hProcess, (DWORD_PTR)StartAddress);
                    ModuleBaseName = (LPSTR)malloc(256);
                    GetModuleBaseNameA(hProcess, (HMODULE)UnresolvedModuleBase, ModuleBaseName, 256);

                    GetStartAndEndFromPdata(FullExeName, UnresolvedModuleBase, &StartAddressBegin, &StartAddressEnd, StartAddress);

                    if (StartAddressEnd != 0 && StartAddressBegin != 0)
                    {
                        printf("[+] Resolved via manual pdata query\n");
                        printf("[+] StartAddressBegin: 0x%llx\n", StartAddressBegin);
                        printf("[+] StartAddressEnd: 0x%llx\n", StartAddressEnd);
                    }
                    // Maybe we are working with an exe base with no pdata, so let's use .text range
                    else if (strstr(ModuleBaseName, ".exe") != NULL)
                    {
                        GetTextSectionRange(FullExeName, UnresolvedModuleBase, &StartAddressBegin, &StartAddressEnd);
                        printf("[+] Resolved via offsets of checking the .text section of the exe\n");
                        printf("[+] StartAddressBegin: 0x%llx\n", StartAddressBegin);
                        printf("[+] StartAddressEnd: 0x%llx\n", StartAddressEnd);
                    }
                    // pdata query manual doesn't always work, so here is fallback
                    else
                    {
                        SymFromAddr(hProcess, (DWORD64)StartAddress, &displacement, pSymbolInfo);
                        printf("[+] Resolved via SymFromAddr\n");
                        printf("[+] StartAddressBegin: %s\n", pSymbolInfo->Name);
                        StartAddressSymbol = pSymbolInfo->Name;

                    }
                    free(ModuleBaseName);

                }
                if (!rt == NULL)
                {
                    StartAddressBegin = (PBYTE)temp + rt->BeginAddress;
                    StartAddressEnd = (PBYTE)temp + rt->EndAddress;
                    printf("[+] Resolved via RtlLookupFunctionEntry\n");
                    printf("[+] StartAddressBegin: 0x%llx\n", StartAddressBegin);
                    printf("[+] StartAddressEnd: 0x%llx\n", StartAddressEnd);
                }

                printf("[+] Thread ID: %d\n", ThreadList[i]->dwTid);
                printf("[+] Process ID: %d\n", ThreadList[i]->dwPid);

                if (SymFromAddr(hProcess, (DWORD64)StartAddress, &displacement, pSymbolInfo))
                {
                    printf("[+] Start Address: %s + 0x%llx\n", pSymbolInfo->Name, displacement);
                }
                else
                {
                    UnresolvedModuleBase = (PVOID)GetModuleBaseAddress(hProcess, (DWORD_PTR)StartAddress);
                    if (UnresolvedModuleBase != 0)
                    {
                        ModuleBaseName = (LPSTR)malloc(256);
                        GetModuleBaseNameA(hProcess, (HMODULE)UnresolvedModuleBase, ModuleBaseName, 256);
                        printf("[+] Start Address: %s + 0x%llx\n", ModuleBaseName, (PBYTE)StartAddress - UnresolvedModuleBase);
                        free(ModuleBaseName);
                    }

                }
                printf("Frame        -> Stack        | RetAddr\n");
                printf("======================================\n");
                // Step 6: Walk the stack frames
                CONTEXT context = { 0 };
                context.ContextFlags = CONTEXT_FULL;
                GetThreadContext(hThread, &context);

                STACKFRAME_EX  stackFrame = { 0 };
                stackFrame.StackFrameSize = sizeof(STACKFRAME_EX);

                // Initialize the stack frame
                stackFrame.AddrPC.Mode = AddrModeFlat;
                stackFrame.AddrPC.Offset = context.Rip; // Program Counter (PC) address
                stackFrame.AddrFrame.Mode = AddrModeFlat;
                stackFrame.AddrFrame.Offset = context.Rbp; // Base Pointer (BP) address
                stackFrame.AddrStack.Mode = AddrModeFlat;
                stackFrame.AddrStack.Offset = context.Rsp; // Stack Pointer (SP) address

                while (StackWalkEx(
                    IMAGE_FILE_MACHINE_AMD64,      // Architecture
                    hProcess,                      // Process handle
                    hThread,                       // Thread handle 
                    &stackFrame,                   // Current stack frame
                    &context,                      // Current thread context
                    NULL,                          // Read memory function (use default)
                    SymFunctionTableAccess64,      // Function table access function
                    SymGetModuleBase64,            // Module base address function
                    NULL,                          // Address translation function
                    SYM_STKWALK_DEFAULT
                ))
                {

                    DWORD64 symbolAddress = stackFrame.AddrPC.Offset;

                    // Resolveable Symbol
                    if (SymFromAddr(hProcess, symbolAddress, &displacement, pSymbolInfo))
                    {
                        if (displacement == 0)
                            printf("0x%llx -> 0x%llx (0x%llx) | %s\n", stackFrame.AddrFrame.Offset, stackFrame.AddrStack.Offset, stackFrame.AddrStack.Offset - stackFrame.AddrStack.Offset, pSymbolInfo->Name);
                        else
                            printf("0x%llx -> 0x%llx (0x%llx) | %s + 0x%llx\n", stackFrame.AddrFrame.Offset, stackFrame.AddrStack.Offset, stackFrame.AddrFrame.Offset - stackFrame.AddrStack.Offset, pSymbolInfo->Name, displacement);
                    }
                    else
                    {
                        // unresolveable Symbol; Offset to some image base
                        UnresolvedModuleBase = (PVOID)GetModuleBaseAddress(hProcess, symbolAddress);
                        if (UnresolvedModuleBase != 0)
                        {
                            ModuleBaseName = (LPSTR)malloc(256);
                            GetModuleBaseNameA(hProcess, (HMODULE)UnresolvedModuleBase, ModuleBaseName, 256);
                            printf("0x%llx -> 0x%llx (0x%llx) | %s + 0x%llx\n", stackFrame.AddrFrame.Offset, stackFrame.AddrStack.Offset, stackFrame.AddrFrame.Offset - stackFrame.AddrStack.Offset, ModuleBaseName, (PBYTE)symbolAddress - UnresolvedModuleBase);
                            free(ModuleBaseName);
                        }

                        // Leaked Stack Value
                        else
                        {
                            printf("0x%llx -> 0x%llx (0x%llx) | 0x%llx\n", stackFrame.AddrFrame.Offset, stackFrame.AddrStack.Offset, stackFrame.AddrFrame.Offset - stackFrame.AddrStack.Offset, symbolAddress);
                        }
                    }
                    if (symbolAddress >= (DWORD64)StartAddressBegin && symbolAddress <= (DWORD64)StartAddressEnd)
                    {
                        FoundStartAddress = 1;
                    }
                    else if (StartAddressSymbol != NULL)
                    {
                        if (strcmp(pSymbolInfo->Name, StartAddressSymbol) == 0)
                            FoundStartAddress = 1;
                    }
                }
                if (FoundStartAddress == 0)
                {
                    printf("[!] WE COULD NOT FIND THE STARTADDRESS OF THIS THREAD IN THE WALK!\n");
                    printf("[!] START ADDRESS: 0x%llx\n", StartAddress);
                    printf("[!] NAME: %s\n", FullExeName);
                }
                SymCleanup(hProcess);
                CloseHandle(hThread);
                return;
            }
            else
            {
                printf("[!] Couldn't Open Thread %d! for PID %d\n", ThreadList[i]->dwTid, ThreadList[i]->dwPid);
                SymCleanup(hProcess);
                CloseHandle(hProcess);
                return;
            }
        }
    }
    printf("[+] We're done here\n");
    return;

}

// GPT Helpers
DWORD GetProcessIDByName(const wchar_t* processName) {
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0; // Could not take snapshot
    }

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                // Process found, return process ID
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0; // Process not found
}

DWORD GetMainThreadID(DWORD processID) {
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0; // Could not take snapshot
    }

    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processID) {
                // Main thread found, return thread ID
                CloseHandle(snapshot);
                return threadEntry.th32ThreadID;
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    CloseHandle(snapshot);
    return 0; // Main thread not found
}

int main(int argc, char* argv[])
{
    SingleProc(GetProcessIDByName(L"pdata.exe"), GetMainThreadID(GetProcessIDByName(L"pdata.exe")));
}