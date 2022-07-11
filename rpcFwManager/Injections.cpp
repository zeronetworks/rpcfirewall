#include "stdafx.h"
#include "common.h"

typedef std::vector<std::pair<DWORD, std::wstring>> ProcVector;

void hookProcessLoadLibrary(DWORD processID, WCHAR* dllToInject)  {

	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, false, processID);
	if (hProcess == nullptr)
	{
		_tprintf(TEXT("OpenProcess failed for pid %u: [%d]\n"), processID, GetLastError());
		return;
	}

	const char* szInjectionDLLName = _bstr_t(dllToInject);

	void* LLParam = (LPVOID)VirtualAllocEx(hProcess, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (LLParam == nullptr)
	{
		_tprintf(TEXT("Error when calling VirtualAllocEx %d \n"), GetLastError());
		return;
	}

	if (WriteProcessMemory(hProcess, LLParam, szInjectionDLLName, strlen(szInjectionDLLName), 0) == 0)
	{
		_tprintf(TEXT("Error when calling WriteProcessMemory %d \n"), GetLastError());
		return;
	}

	FARPROC pLoadLib = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (pLoadLib == nullptr)
	{
		_tprintf(TEXT("Error when calling GetProcAddress %d \n"), GetLastError());
		return;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLib, LLParam, 0, 0);
	if (hRemoteThread == nullptr)
	{
		_tprintf(TEXT("Error when calling CreateRemoteThread %d \n"), GetLastError());
		return;
	}

	CloseHandle(hRemoteThread);
}

std::pair<bool, bool> containsRPCModules(DWORD dwPID)
{
	bool containsRpcRuntimeModule = false;
	bool containsRpcFirewallModule = false;

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		//_tprintf(TEXT("Error when calling CreateToolhelp32Snapshot for pid %u: %d\n"), dwPID,GetLastError());
		return std::make_pair(containsRpcRuntimeModule, containsRpcFirewallModule);;
	}

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32))
	{
		_tprintf(TEXT("Error when calling Module32First: %d"),GetLastError());
		CloseHandle(hModuleSnap);
		return std::make_pair(containsRpcRuntimeModule, containsRpcFirewallModule);;
	}

	while (Module32Next(hModuleSnap, &me32))
	{
		if (_tcsstr(me32.szModule, _T("rpcrt4.dll")) || _tcsstr(me32.szModule, _T("RPCRT4.dll")))
		{
			//_tprintf(TEXT("Process %d contains RPC module!\n"), dwPID);
			containsRpcRuntimeModule = true;
		}

		if (_tcsstr(me32.szModule, RPC_FW_DLL_NAME))
		{
			//_tprintf(TEXT("Process %d contains RPCFW module!\n"), dwPID);
			containsRpcFirewallModule = true;
		}
	}

	CloseHandle(hModuleSnap);
	return std::make_pair(containsRpcRuntimeModule, containsRpcFirewallModule);
}

bool containsRPCFWModule(DWORD dwPID)
{
	HANDLE hModuleSnap;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		//_tprintf(TEXT("Error when calling CreateToolhelp32Snapshot for pid %u: %d\n"), dwPID,GetLastError());
		return false;
	}

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32))
	{
		_tprintf(TEXT("Error when calling Module32First: %d"), GetLastError());
		CloseHandle(hModuleSnap);
		return false;
	}

	while (Module32Next(hModuleSnap, &me32))
	{
		if (compareStringsCaseinsensitive(me32.szModule, RPC_FW_DLL_NAME))
		{
			//_tprintf(TEXT("Process %d contains RPCFW module!\n"), dwPID);
			CloseHandle(hModuleSnap);
			return true;
		}
	}

	CloseHandle(hModuleSnap);
	return false;
}

void classicHookRPCProcesses(DWORD processID, wchar_t* dllToInject)
{
	std::pair<bool, bool> containsModules = containsRPCModules(processID);
	bool containsRPC = containsModules.first;
	bool containsRPCFW = containsModules.second;

	if (containsRPC && !containsRPCFW)
	{
		hookProcessLoadLibrary(processID, dllToInject);
	}
}

ProcVector getProtectedProcesses()
{
	ProcVector procVector;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bool bProcess = Process32FirstW(hTool32, &pe32);

	if (bProcess == true) {
		while ((Process32Next(hTool32, &pe32)) == TRUE)
		{
			if (containsRPCFWModule(pe32.th32ProcessID))
			{
				procVector.push_back(std::make_pair(pe32.th32ProcessID, pe32.szExeFile));
			}
		}
	}
	CloseHandle(hTool32);

	return procVector;
}

void printProcessesWithRPCFW()
{
	outputMessage(L"\tProtected processes:");
	outputMessage(L"\t-------------------");

	ProcVector procVec = getProtectedProcesses();
	size_t vSize = procVec.size();
	size_t i = 0;

	for (i; i < vSize; i++)
	{
		std::wstring pid = std::to_wstring(procVec[i].first);
		std::wstring procName = procVec[i].second;


		outputMessage((L"\t" + pid + L" : " + procName).c_str());
	}
	if (i == 0) outputMessage(L"\tRPC Firewall not installed on any process.");

}

ProcVector getRelevantProcVector(DWORD pid, std::wstring& pName)
{
	ProcVector procVector;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bool bProcess = Process32FirstW(hTool32, &pe32);

	if (bProcess == true) {
		while ((Process32Next(hTool32, &pe32)) == TRUE)
		{
			if (!pName.empty() && compareStringsCaseinsensitive(pe32.szExeFile, (wchar_t*)pName.c_str()))
			{
				procVector.push_back(std::make_pair(pe32.th32ProcessID, pe32.szExeFile));
			}
			else if (pid == 0)
			{
				procVector.push_back(std::make_pair(pe32.th32ProcessID, pe32.szExeFile));
			}
			else if (pid == pe32.th32ProcessID)
			{
				procVector.push_back(std::make_pair(pe32.th32ProcessID, pe32.szExeFile));
			}
		}
	}
	CloseHandle(hTool32);

	return procVector;
}

void crawlProcesses(DWORD pid, std::wstring& pName)
{
	ProcVector procToHook = getRelevantProcVector(pid, pName);

	unsigned int i;
	size_t vSize = procToHook.size();
	for (i = 0; i < vSize; i++)
	{
		DWORD pid = procToHook[i].first;
		std::wstring procName = procToHook[i].second;

		if (pid != GetProcessId(nullptr))
		{
			_tprintf(TEXT("Protecting %d : %s\n"), pid, procName.c_str());
			classicHookRPCProcesses(pid, (wchar_t*)RPC_FW_DLL_NAME);
		}
		else _tprintf(TEXT("Skipping self %d : %s\n"), pid, procName.c_str());
	}
}

void crawlProcesses(DWORD pid)
{
	std::wstring noProcName;
	crawlProcesses(pid, noProcName);
}