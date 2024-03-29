#pragma once
#include "stdafx.h"

typedef LONG KPRIORITY;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

struct RpcStringWrapper
{
    RPC_WSTR* getRpcPtr()
    {
        return (RPC_WSTR*)&str;
    }

    ~RpcStringWrapper()
    {
        if (str != nullptr)
        {
            RpcStringFree(getRpcPtr());
        }
    }

    wchar_t* str = nullptr;
};

struct RpcBindingWrapper
{
    ~RpcBindingWrapper()
    {
        if (binding != nullptr)
        {
            RpcBindingFree(&binding);
        }
    }

    RPC_BINDING_HANDLE binding = nullptr;
};


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);

// Define the SYSTEM_EXTENDED_THREAD_INFORMATION structure
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER Reserved1[3];
    ULONG Reserved2;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG Reserved3;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _UNICODE_STRING_X {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_X;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING_X ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

HANDLE hookProcessLoadLibrary(HANDLE hProcess, WCHAR* dllToInject);

bool ContainsRPCModule(DWORD dwPID);

void classicHookRPCProcesses(DWORD processID, wchar_t* dllToInject);

bool PESelfInjectToRemoteProcess(DWORD processID, wchar_t* procName);

void crawlProcesses(DWORD, std::wstring& );

void crawlProcesses(DWORD);

void printProcessesWithRPCFW();

void printRPCEndpoints();

void printProtectedProcesses();