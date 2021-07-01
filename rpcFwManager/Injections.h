#pragma once
#include "stdafx.h"

HANDLE hookProcessLoadLibrary(HANDLE hProcess, WCHAR* dllToInject);

BOOL ContainsRPCModule(DWORD dwPID);

void classicHookRPCProcesses(DWORD processID, TCHAR* dllToInject);

BOOL PESelfInjectToRemoteProcess(DWORD processID, TCHAR* procName);