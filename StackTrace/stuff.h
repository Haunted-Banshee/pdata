#pragma once
//#include <Windows.h>
#include <winternl.h>

#define ThreadQuerySetWin32StartAddress 0x09
#define STATUS_SUCCESS              ((NTSTATUS) 0x00000000)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS) 0x00000001)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

typedef NTSTATUS(NTAPI* pNtQIT)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* PFN_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct THREAD_INFO {

    PWSTR wProcessName;

    DWORD dwPid;
    DWORD dwTid;

    PVOID StartAddress;

} THREAD, * PTHREAD;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    FILETIME CreateTime;
    FILETIME UserTime;
    FILETIME KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    ULONG pad1;
    ULONG ProcessId;
    ULONG pad2;
    ULONG InheritedFromProcessId;
    ULONG pad3;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T WeDontNeedThishaha[2];
    ULONG WeDontNeedThishaha2;
    SIZE_T WeDontNeedThishaha3[8];
    ULONG_PTR PrivatePageCount;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION ThreadInfos[1];
} MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;