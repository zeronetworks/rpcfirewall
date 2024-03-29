#include "stdafx.h"
#include "common.h"
#include <iostream>
#include <iomanip>
#include "iphlpapi.h"
#include <algorithm>

typedef std::vector<std::pair<DWORD, std::wstring>> ProcVector;

typedef std::vector<std::tuple<DWORD, std::wstring, DWORD>> ProcProtectionStatusVector;

PFN_NtQuerySystemInformation pGlobalNtQuerySystemInformation = nullptr;

void hookProcessLoadLibrary(DWORD processID, WCHAR* dllToInject)  {

	std::wstring wstr(dllToInject);
	std::string szInjectionDLLName(wstr.begin(), wstr.end());

	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, false, processID);
	if (hProcess == nullptr)
	{
		_tprintf(TEXT("OpenProcess failed for pid %u: [%d]\n"), processID,GetLastError());
		return;
	}

	void* LLParam = (LPVOID)VirtualAllocEx(hProcess, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (LLParam == nullptr)
	{
		_tprintf(TEXT("Error when calling VirtualAllocEx %d \n"), GetLastError());
		CloseHandle(hProcess);
		return;
	}

	if (WriteProcessMemory(hProcess, LLParam, szInjectionDLLName.c_str(), strlen(szInjectionDLLName.c_str()), 0) == 0)
	{
		_tprintf(TEXT("Error when calling WriteProcessMemory %d \n"), GetLastError());
		CloseHandle(hProcess);
		return;
	}
	
	FARPROC pLoadLib = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (pLoadLib == nullptr)
	{
		_tprintf(TEXT("Error when calling GetProcAddress %d \n"), GetLastError());
		CloseHandle(hProcess);
		return;
	}
	
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLib, LLParam, 0, 0);
	if (hRemoteThread == nullptr)
	{
		_tprintf(TEXT("Error when calling CreateRemoteThread %d \n"), GetLastError());
		CloseHandle(hProcess);
		return;
	}

	CloseHandle(hProcess);
	CloseHandle(hRemoteThread);
}

bool armNtQuerySysInfoFunction()
{
	if (pGlobalNtQuerySystemInformation != nullptr) return true;

	HMODULE hNtDll = LoadLibrary(L"ntdll.dll");
	if (hNtDll == nullptr) {
		outputMessage(L"Error: armNtQuerySysInfoFunction could not load ntdll.dll...\n");
		return false;
	}

	pGlobalNtQuerySystemInformation = reinterpret_cast<PFN_NtQuerySystemInformation>(GetProcAddress(hNtDll, "NtQuerySystemInformation"));
	if (pGlobalNtQuerySystemInformation == nullptr) {
		outputMessage(L"Error: Couldn't find NtQuerySystemInformation function\n");
		FreeLibrary(hNtDll);
		return false;
	}

	return true;
}

bool isProcessSuspended(DWORD dwPID)
{
	if (!armNtQuerySysInfoFunction()) return false;

	ULONG bufferSize = 0;
	NTSTATUS status = pGlobalNtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &bufferSize);
	if (bufferSize == 0) {
		outputMessage(L"Error: Couldn't call NtQuerySystemInformation with SystemProcessInformation\n");
		return false;
	}

	// Allocate buffer to store thread information
	PVOID buffer = malloc(bufferSize);
	if (buffer == nullptr) {
		outputMessage(L"Error: Failed to allocate buffer.\n");
		return false;
	}

	// Query system information again with the allocated buffer
	status = pGlobalNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, nullptr);
	if (!NT_SUCCESS(status)) {
		outputMessage(L"Error: Failed to query NtQuerySystemInformation again.\n");
		free(buffer);
		return false;
	}

	// Process the thread information
	PSYSTEM_PROCESS_INFORMATION pProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
	while (pProcessInfo->NextEntryOffset > 0) {
		if ((DWORD)pProcessInfo->UniqueProcessId == dwPID)
		{
			PSYSTEM_THREAD_INFORMATION pThreadInfo = (PSYSTEM_THREAD_INFORMATION)((PBYTE)pProcessInfo + sizeof(SYSTEM_PROCESS_INFORMATION));
			for (int t = 2; t <= pProcessInfo->NumberOfThreads; t++)
			{
				if (pThreadInfo->ThreadState != 5 || pThreadInfo->WaitReason != 5)
				{
					free(buffer);
					return false;
				}
				pThreadInfo = (PSYSTEM_THREAD_INFORMATION)((PBYTE)pThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION));
			}
			outputMessage(L"Process is suspended, skipping.\n");
			free(buffer);
			return true;
		}
		// Move to the next thread information block
		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcessInfo + pProcessInfo->NextEntryOffset);
	}
	// Clean up
	free(buffer);
	return false;

}

std::pair<bool,bool> containsRPCModules(DWORD dwPID)
{
	bool containsRpcRuntimeModule = false;
	bool containsRpcFirewallModule = false;

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		//_tprintf(TEXT("Error when calling CreateToolhelp32Snapshot for pid %u: %d\n"), dwPID,GetLastError());
		CloseHandle(hModuleSnap);
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
	};

	CloseHandle(hModuleSnap);
	return std::make_pair(containsRpcRuntimeModule, containsRpcFirewallModule);;
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
	};

	CloseHandle(hModuleSnap);
	return false;
}

void classicHookRPCProcesses(DWORD processID, wchar_t* dllToInject)
{
	if (isProcessSuspended(processID)) return;

	std::pair<bool,bool> containsModules = containsRPCModules(processID);
	bool containsRPC = containsModules.first;
	bool containsRPCFW = containsModules.second;

	if ( containsRPC && !containsRPCFW) 
	{
		hookProcessLoadLibrary(processID, dllToInject);
	}
}

ProcProtectionStatusVector getProtectedProcesses()
{
	ProcProtectionStatusVector procVector;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bool bProcess = Process32FirstW(hTool32, &pe32);

	if (bProcess == true) {
		while ((Process32Next(hTool32, &pe32)) == TRUE)
		{
			HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.th32ProcessID);
			if (ph != nullptr)
			{
				PROCESS_PROTECTION_LEVEL_INFORMATION ppli;
				if (GetProcessInformation(ph, ProcessProtectionLevelInfo, &ppli, sizeof(PROCESS_PROTECTION_LEVEL_INFORMATION)))
				{
					if (ppli.ProtectionLevel < PROTECTION_LEVEL_NONE)
					{
						procVector.push_back(std::make_tuple(pe32.th32ProcessID, pe32.szExeFile, ppli.ProtectionLevel));
					}

				}
				CloseHandle(ph);
			}
		}
	}
	CloseHandle(hTool32);

	return procVector;
}

std::wstring extractValueInBrackets(const std::wstring& str) {
	std::wstring v;

	size_t startPos = str.find(L'[');
	if (startPos != std::wstring::npos) {
		size_t endPos = str.find(L']', startPos);
		if (endPos != std::wstring::npos) {
			v = str.substr(startPos + 1, endPos - startPos - 1);
		}
	}
	return v;
}

ProcVector getRpcFirewalledProcesses()
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

std::wstring GetProtectionLevelString(DWORD protectionLevel) {
	switch (protectionLevel) {
	case PROTECTION_LEVEL_WINTCB:
		return L"WinTcb";
	case PROTECTION_LEVEL_WINTCB_LIGHT:
		return L"WinTcb Light";
	case PROTECTION_LEVEL_WINDOWS:
		return L"Windows";
	case PROTECTION_LEVEL_WINDOWS_LIGHT:
		return L"Windows Light";
	case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
		return L"AntiMalware Light";
	case PROTECTION_LEVEL_LSA_LIGHT:
		return L"LSA Light";
	default:
		return L"Unprotected";
	}
}

std::wstring getProtectionStateByPid(DWORD pid)
{
	std::wstring pil;
	HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
	if (ph != nullptr)
	{
		PROCESS_PROTECTION_LEVEL_INFORMATION ppli;
		if (GetProcessInformation(ph, ProcessProtectionLevelInfo, &ppli, sizeof(PROCESS_PROTECTION_LEVEL_INFORMATION)))
		{
			pil = GetProtectionLevelString(ppli.ProtectionLevel);
		}
		CloseHandle(ph);
	}
	return pil;
}

RpcInterface getRpcInterfacesFromParams(std::wstring uuid, std::wstring annotaion, std::wstring binding)
{
	RpcInterface* RpcInt = new RpcInterface();

	RpcInt->uuid = uuid;
	RpcInt->szAnnot = annotaion;
	RpcInt->binding = binding;

	return *RpcInt;
}

void getPIDForEndpoints(RpcInterfaceVector& rpcVector, PMIB_TCPTABLE_OWNER_PID pTcpTable)
{
	for (size_t rpcIntNumber = 0; rpcIntNumber < rpcVector.size(); ++rpcIntNumber)
	{
		RpcInterface& rpcInt = rpcVector[rpcIntNumber];

		if (rpcInt.pid == 0)
		{
			std::wstring endpoint = extractValueInBrackets(rpcInt.binding);
			if (endpoint.find(L"\\") != std::wstring::npos)
			{
				endpoint = L"\\\\." + endpoint;

				HANDLE hNamedPipe = CreateFile(endpoint.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

				if (hNamedPipe != INVALID_HANDLE_VALUE) {

					DWORD dwProcessId;
					BOOL success = GetNamedPipeServerProcessId(hNamedPipe, &dwProcessId);
					if (success)
					{
						rpcInt.pid = dwProcessId;
					}
					else
					{
						//_tprintf(TEXT("GetNamedPipeServerProcessId failed!\n"));
					}

					CloseHandle(hNamedPipe); // Close the handle when done
				}
				else {

					//_tprintf(TEXT("Invalid handle!\n"));
				}

			}
			else
			{
				wchar_t* endPtr;
				unsigned long portVal = std::wcstoul(endpoint.c_str(), &endPtr, 10);

				if (!endpoint.empty() && *endPtr == L'\0') {

					for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
						if (pTcpTable->table[i].dwLocalPort == htons(portVal)) {
							rpcInt.pid = pTcpTable->table[i].dwOwningPid;
							break;
						}
					}
				}

			}

			if (rpcInt.pid > 0) {
				rpcInt.ppl = getProtectionStateByPid(rpcInt.pid);
			}
			else
			{
				//_tprintf(TEXT("Zero PID!\n"));
			}
		}
	}
}

RpcInterfaceVector getRPCEndpointVector()
{
	RpcInterfaceVector intVector;
	RpcBindingWrapper hRpc;
	RPC_EP_INQ_HANDLE hInq = nullptr;
	RpcStringWrapper szStringBinding;

	RPC_STATUS rpcErr = RpcMgmtEpEltInqBegin(hRpc.binding,RPC_C_EP_ALL_ELTS,nullptr,NULL,nullptr,&hInq);

	if (rpcErr != RPC_S_OK) {
		_tprintf(TEXT("RpcMgmtEpEltInqBegin error: %d : %s\n"), rpcErr);
	}
	else
	{
		do {
			RPC_IF_ID IfId;
			RPC_IF_ID_VECTOR* pVector;
			RPC_STATS_VECTOR* pStats;
			RpcBindingWrapper hEnumBind;
			UUID uuid;
			RpcStringWrapper szAnnot;

			rpcErr = RpcMgmtEpEltInqNext(hInq,&IfId,&hEnumBind.binding,&uuid,szAnnot.getRpcPtr());

			if (rpcErr == RPC_S_OK) {
				RpcStringWrapper uuidStr;
				RpcStringWrapper comUUID;
				RpcStringWrapper princName;

				if (RpcBindingToStringBinding(hEnumBind.binding, uuidStr.getRpcPtr()) == RPC_S_OK) 
				{
					std::wstring wstrBind(uuidStr.str);

					if (wstrBind.find(L"ncalrpc") == std::wstring::npos)
					{

						if (UuidToString(&(IfId.Uuid), uuidStr.getRpcPtr()) != RPC_S_OK) {
								// Error...?
						}
	
						if (UuidToString(&uuid, comUUID.getRpcPtr()) != RPC_S_OK) {

							// Error...?
						}

						RpcBindingWrapper hIfidsBind;
						rpcErr = RpcBindingFromStringBinding((RPC_WSTR)wstrBind.c_str(), &hIfidsBind.binding);

						if (rpcErr != RPC_S_OK) {
							// Error...?
							continue;
						}

						if ((rpcErr = RpcMgmtInqIfIds(hIfidsBind.binding, &pVector)) == RPC_S_OK) {
							unsigned int i;
							for (i = 0; i < pVector->Count; i++) {
								RpcStringWrapper localUuidStr;
								UuidToString(&pVector->IfId[i]->Uuid, localUuidStr.getRpcPtr());

								intVector.push_back(getRpcInterfacesFromParams(std::wstring(localUuidStr.str), std::wstring(szAnnot.str), wstrBind));

								LPCWSTR szIfIIDInfo = NULL;
							}
							RpcIfIdVectorFree(&pVector);
						}
						else {
							intVector.push_back(getRpcInterfacesFromParams(std::wstring(uuidStr.str), std::wstring(szAnnot.str), wstrBind));
						}

					}
				}
			}
		} while (rpcErr != RPC_X_NO_MORE_ENTRIES);
	}
	return intVector;

}

void removeDuplicates(RpcInterfaceVector& rpcVector) {
	// Iterate through the vector
	for (size_t i = 0; i < rpcVector.size(); ++i) {
		// Store current entry for comparison
		RpcInterface& currentEntry = rpcVector[i];

		// Iterate through the vector starting from the next entry
		for (size_t j = i + 1; j < rpcVector.size(); ) {
			// Check if pid, uuid, and binding are the same
			if (currentEntry.pid == rpcVector[j].pid &&
				currentEntry.uuid == rpcVector[j].uuid &&
				currentEntry.binding == rpcVector[j].binding) {
				// Erase duplicate entry
				rpcVector.erase(rpcVector.begin() + j);
			}
			else {
				// Move to the next entry
				++j;
			}
		}
	}
}

void fixZeroPIDEntriesInRpcVectorAndSort(RpcInterfaceVector& vec) {

	std::sort(vec.begin(), vec.end(),
		[](const RpcInterface& a, const RpcInterface& b) {
			return a.pid < b.pid;
		});

	for (size_t i = 0; i < vec.size(); ++i) {
		if (vec[i].pid == 0) {
			for (size_t j = i + 1; j < vec.size(); ++j) {
				if (vec[j].binding == vec[i].binding && vec[j].pid != 0) {
					vec[i].pid = vec[j].pid;
					vec[i].ppl = vec[j].ppl;
					break;
				}
			}
		}
	}

	removeDuplicates(vec);

	std::sort(vec.begin(), vec.end(),
		[](const RpcInterface& a, const RpcInterface& b) {
			return a.pid < b.pid;
		});
}

void printRPCEndpoints()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		// Bad...
	}

	DWORD dwSize = 0;
	if (GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
	}

	std::vector<char> buffer(dwSize);
	PMIB_TCPTABLE_OWNER_PID pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(&buffer[0]);

	// Retrieve TCP table
	if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
		//Bad...
	}

	RpcInterfaceVector vectorOfInterfaces = getRPCEndpointVector();

	getPIDForEndpoints(vectorOfInterfaces, pTcpTable);

	WSACleanup();

	fixZeroPIDEntriesInRpcVectorAndSort(vectorOfInterfaces);

	// Print the header row
	std::wcout << std::setw(5) << L"PID,"
		<< std::setw(10) << L"ProtectionLevel,"
		<< std::setw(20) << L"Binding,"
		<< std::setw(50) << L"UUID,"
		<< std::setw(20) << L"Annotation"
		<< std::endl;

	// Print each RpcInterface as a row in the table
	for (const RpcInterface& rpcInterface : vectorOfInterfaces) {
		std::wcout << rpcInterface.pid << L","
			<< std::setw(10) << rpcInterface.ppl << L","
			<< std::setw(50) << rpcInterface.binding << L","
			<< std::setw(40) << rpcInterface.uuid << L","
			<< std::setw(20) << rpcInterface.szAnnot
			<< std::endl;
	}
}

void printProtectedProcesses()
{
	outputMessage(L"\tProtected Processes (can't be injected with the RPCFW module)");
	outputMessage(L"\t-------------------");

	ProcProtectionStatusVector procVec = getProtectedProcesses();
	size_t vSize = procVec.size();
	size_t i = 0;

	for (i; i < vSize; i++)
	{
		std::wstring pid = std::to_wstring(std::get<0>(procVec[i]));
		std::wstring procName = std::get<1>(procVec[i]);
		std::wstring protectionLevel = GetProtectionLevelString(std::get<2>(procVec[i]));
		std::wstring tabs;
		if (protectionLevel.length() < 8) {
			tabs = L"\t\t\t";
		}
		else if (protectionLevel.length() < 16) {
			tabs = L"\t\t";
		}
		else {
			tabs = L"\t";
		}


		outputMessage((L"\t" + pid + L"\t" + protectionLevel + tabs + procName).c_str());
	}
	if (i == 0) outputMessage(L"\No protected processes found.");
}

void printProcessesWithRPCFW()
{
	outputMessage(L"\tRPC Firewalled processes:");
	outputMessage(L"\t-------------------");

	ProcVector procVec = getRpcFirewalledProcesses();
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