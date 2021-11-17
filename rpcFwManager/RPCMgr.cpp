// RPCrawler.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "stdafx.h"

HANDLE globalMappedMemory = NULL;
HANDLE globalUnprotectlEvent = NULL;

enum class eventSignal {signalSetEvent, signalResetEvent};

typedef std::vector<std::pair<DWORD, std::basic_string<TCHAR>>> ProcVector;

CHAR configBuf[MEM_BUF_SIZE];

void concatArguments(int argc, _TCHAR* argv[], TCHAR command[])
{
	_tcscpy_s(command, MAX_PATH *2, argv[0]);
	
	for (int i = 1; i < argc; i++)
	{
		_tcscat_s(command, MAX_PATH * 2, TEXT(" "));
		_tcscat_s(command, MAX_PATH * 2, argv[i]);
	}

	_tcscat_s(command, MAX_PATH * 2, TEXT(" /elevated"));
}

ProcVector getRelevantProcVector(DWORD pid, TCHAR* pName)
{
	ProcVector procVector;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL bProcess = Process32FirstW(hTool32, &pe32);

	if (bProcess == TRUE) {
		while ((Process32Next(hTool32, &pe32)) == TRUE) 
		{
			if (pName != NULL && compareStringsCaseinsensitive(pe32.szExeFile, pName))
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

void crawlProcesses(DWORD pid, TCHAR* pName) 
{
	ProcVector procToHook = getRelevantProcVector(pid, pName);

	unsigned int i;
	size_t vSize = procToHook.size();
	for (i = 0; i < vSize; i++)
	{
		DWORD pid = procToHook[i].first;
		std::basic_string<TCHAR> procName = procToHook[i].second;

		_tprintf(TEXT("Protecting %d : %s\n"),pid,procName.c_str());
		classicHookRPCProcesses(pid, (TCHAR*)RPC_FW_DLL_NAME);
	}
}

void getHelp()
{
	_tprintf(TEXT("Usage: rpcFwManager /[Command]\n\n"));
	_tprintf(TEXT("The following commands are available:\n\n"));
	_tprintf(TEXT("install\t\t - configure RPCFWP EventLog & put DLLs in the %%SystemRoot%%\\system32 folder\n"));
	_tprintf(TEXT("uninstall\t - remove RPCFWP EventLog configuration & remove DLLs from the %%SystemRoot%%\\system32 folder\n"));
	_tprintf(TEXT("pid\t\t - Protect specified process ID with RPCFWP <no pid protects ALL processes!> \n"));
	_tprintf(TEXT("process\t\t - Protect specified process by name with RPCFWP <no name protects ALL processes!>\n"));
	_tprintf(TEXT("unprotect\t - Remove RPCFirewall from any protected process \n"));
	_tprintf(TEXT("update\t\t - notify the rpcFirewall.dll on configuration changes \n"));
}

void deleteFileFromSysfolder(std::basic_string<TCHAR> fileName)
{

	TCHAR  destPath[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetSystemDirectory(destPath, INFO_BUFFER_SIZE))
	{
		_tprintf(TEXT("ERROR: Couldn't get the system directory [%d].\n"), GetLastError());
		return;
	}

	std::basic_string<TCHAR> destPathStr = destPath;
	destPathStr += TEXT("\\");
	destPathStr += fileName;

	if (!DeleteFile(destPathStr.c_str()))
	{
		DWORD LastError = GetLastError();
		if (LastError != ERROR_FILE_NOT_FOUND)
		{
			_tprintf(TEXT("ERROR: %s delete operation from system folder failed [%d].\n"), destPathStr.c_str(), GetLastError());
			return;
		}
	}
}

void writeFileToSysfolder(std::basic_string<TCHAR> sourcePath, std::basic_string<TCHAR> sourceFileName)
{

	TCHAR  destPath[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetSystemDirectory(destPath, INFO_BUFFER_SIZE))
	{
		_tprintf(TEXT("ERROR: Couldn't get the system directory [%d].\n"), GetLastError());
		return;
	}

	std::basic_string<TCHAR> destPathStr = destPath;
	destPathStr += TEXT("\\");
	destPathStr += sourceFileName;

	if (!CopyFile(sourcePath.c_str(), destPathStr.c_str(), FALSE))
	{
		_tprintf(TEXT("ERROR: %s copy to system folder failed [%d].\n"), sourcePath.c_str(), GetLastError());
		return;
	}
}

std::basic_string<TCHAR> getFullPathOfFile(const std::basic_string<TCHAR> &filename)
{
	TCHAR  filePath[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetCurrentDirectory(bufCharCount, filePath))
	{
		_tprintf(TEXT("ERROR: Couldn't get the current directory [%d].\n"), GetLastError());
		return std::basic_string<TCHAR>();
	}
	_tcscat_s(filePath, TEXT("\\"));

	return std::basic_string<TCHAR>(filePath) + _T("\\") + filename;
}

BOOL createSecurityAttributes(SECURITY_ATTRIBUTES * psa, PSECURITY_DESCRIPTOR psd)
{
	if (InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) != 0)
	{
		if (SetSecurityDescriptorDacl(psd, TRUE, NULL, FALSE) != 0)
		{
			(*psa).nLength = sizeof(*psa);
			(*psa).lpSecurityDescriptor = psd;
			(*psa).bInheritHandle = FALSE;

			return TRUE;
		}
		else
		{
			_tprintf(TEXT("SetSecurityDescriptorDacl failed : %d.\n"), GetLastError());
		}
	}
	else
	{
		_tprintf(TEXT("InitializeSecurityDescriptor failed : %d.\n"), GetLastError());
	}

	return FALSE;
}

HANDLE createGlobalEvent(BOOL manualReset,BOOL initialState, TCHAR* eventName)
{
	HANDLE gEvent = NULL;
	SECURITY_ATTRIBUTES sa = { 0 };
	PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	
	//TODO: return value instead of passing as ref
	if (createSecurityAttributes(&sa, psd))
	{
		gEvent = CreateEvent(&sa, manualReset, initialState, eventName);
		if (gEvent != NULL)
		{
			if (ResetEvent(gEvent) == 0)
			{
				_tprintf(TEXT("Error: ResetEvent for %s failed with %d.\n"), eventName, GetLastError());
			}
		}
		else
		{
			_tprintf(TEXT("Error: could not create or get a global event %s : %d.\n"), eventName, GetLastError());
		}
	}

	LocalFree(psd);

	return gEvent;
}

void createAllGloblEvents()
{
	globalUnprotectlEvent = createGlobalEvent(TRUE, FALSE, (TCHAR*)GLOBAL_RPCFW_EVENT_UNPROTECT);
}

HANDLE mapNamedMemory()
{
	HANDLE hMapFile = NULL;
	SECURITY_ATTRIBUTES sa = { 0 };
	PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

	if (createSecurityAttributes(&sa,psd))
	{
		hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, MEM_BUF_SIZE, GLOBAL_SHARED_MEMORY);
		if (hMapFile == NULL)
		{
			_tprintf(TEXT("Error calling CreateFileMapping %d.\n"), GetLastError());
		}
	}

	LocalFree(psd);

	return hMapFile;
}

CHAR* readConfigFile(DWORD * bufLen)
{
	std::basic_string<TCHAR> cfgFwPath = getFullPathOfFile(std::basic_string<TCHAR>(CONF_FILE_NAME));
	HANDLE hFile = CreateFile(cfgFwPath.c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("No configuration file found %d.\n"), GetLastError());
	}
	else if (!ReadFile(hFile,configBuf, MEM_BUF_SIZE - 1, bufLen,NULL))
	{
		_tprintf(TEXT("ERROR: ReadFile %d.\n"), GetLastError());

	}

	return configBuf;
}

std::basic_string<CHAR> addHeaderToBuffer(DWORD verNumber,CHAR* confBuf, DWORD bufSize)
{
	std::basic_string<CHAR> strToHash = confBuf;
	strToHash.resize(bufSize);
	size_t hashValue = std::hash<std::basic_string<CHAR>>{}(strToHash);

	std::basic_string<CHAR> resultBuf = "ver:" + std::to_string(verNumber) +  " hash:" + std::to_string(hashValue) + "\r\n" + "!start!" + strToHash + "!end!";

	return resultBuf;
}

std::basic_string<CHAR> extractKeyValueFromConfig(std::basic_string<CHAR> confLine, std::basic_string<CHAR> key)
{
	confLine += (" ");
	size_t keyOffset = confLine.find(key);

	if (keyOffset == std::string::npos) return "\0";

	size_t nextKeyOffset = confLine.find(" ", keyOffset + 1);

	if (nextKeyOffset == std::string::npos) return "\0";

	return confLine.substr(keyOffset + key.size(), nextKeyOffset - keyOffset - key.size());
}

DWORD getConfigVersionNumber(CHAR* buff)
{
	std::string buffString(buff);
	std::string version = extractKeyValueFromConfig(buffString, "ver:");

	if (version.empty())
	{
		return 0;
	}

	return std::stoi(version);
}

void readConfigAndMapToMemory()
{
	CHAR* pBuf;
	DWORD bytesRead = 0;
	CHAR* confBuf = readConfigFile(&bytesRead);
	
	if (bytesRead > 0)
	{
		globalMappedMemory = mapNamedMemory();

		if (globalMappedMemory == NULL)
		{
			std::quick_exit(-1);
		}

		pBuf = (CHAR*)MapViewOfFile(globalMappedMemory, FILE_MAP_ALL_ACCESS, 0, 0, MEM_BUF_SIZE);
		if (pBuf == NULL)
		{
			_tprintf(TEXT("Error calling MapViewOfFile %d.\n"), GetLastError());
			CloseHandle(globalMappedMemory);
			std::quick_exit(-1);
		}
		
		DWORD verNumber = getConfigVersionNumber(pBuf);
		std::basic_string<CHAR> confBufHashed = addHeaderToBuffer(verNumber + 1,confBuf, bytesRead);

		memset(pBuf, '\0', MEM_BUF_SIZE);
		CopyMemory((PVOID)pBuf, confBufHashed.c_str(), bytesRead + confBufHashed.length());
	}
}

void sendSignalToGlobalEvent(TCHAR* globalEventName, eventSignal eSig)
{
	HANDLE hEvent = createGlobalEvent(TRUE, FALSE, globalEventName);
	if (hEvent == NULL)
	{
		_tprintf(TEXT("Could not get handle to event %s, error: %d\n"), globalEventName, GetLastError());
		return;
	}

	if (eSig == eventSignal::signalSetEvent)
	{
		if (SetEvent(hEvent) == 0)
		{
			_tprintf(TEXT("Setting the event %s failed: %d.\n"), globalEventName, GetLastError());
		}
	}
	else
	{
		if (ResetEvent(hEvent) == 0)
		{
			_tprintf(TEXT("Resetting the event %s failed: %d.\n"), globalEventName, GetLastError());
		}
	}
}

void cmdInstall()
{
	_tprintf(TEXT("installing RPCFW ...\n"));
	elevateCurrentProcessToSystem();
	
	writeFileToSysfolder(getFullPathOfFile(std::basic_string<TCHAR>(RPC_FW_DLL_NAME)), RPC_FW_DLL_NAME);
	writeFileToSysfolder(getFullPathOfFile(std::basic_string<TCHAR>(RPC_MESSAGES_DLL_NAME)), RPC_MESSAGES_DLL_NAME);

	addEventSource();
}

void cmdUpdate()
{
	readConfigAndMapToMemory();
}

void cmdPid(int argc, _TCHAR* argv[])
{
	elevateCurrentProcessToSystem();
	createAllGloblEvents();
	readConfigAndMapToMemory();
	DWORD procNum = 0;
	if (argc > 2)
	{
		procNum = std::stoi((std::wstring)argv[2], nullptr, 10);
		_tprintf(TEXT("Enabling RPCFW for process : %d\n"), procNum);
		crawlProcesses(procNum, NULL);
	}
	else
	{
		_tprintf(TEXT("Enabling RPCFW for ALL processes\n"));
		crawlProcesses(0, NULL);
	}
}

void cmdUnprotect()
{
	elevateCurrentProcessToSystem();
	_tprintf(TEXT("Dispatching unprotect request...\n"));
	sendSignalToGlobalEvent((TCHAR*)GLOBAL_RPCFW_EVENT_UNPROTECT, eventSignal::signalSetEvent);
}

void cmdProcess(int argc, _TCHAR* argv[])
{
	createAllGloblEvents();
	elevateCurrentProcessToSystem();
	readConfigAndMapToMemory();
	if (argc > 2)
	{
		_tprintf(TEXT("Enabling RPCFW for process : %s\n"), argv[2]);
		crawlProcesses(17, (TCHAR*)argv[2]);
	}
	else
	{
		_tprintf(TEXT("Enabling RPCFW for ALL processes\n"));
		crawlProcesses(0, NULL);
	}
}

void cmdUninstall()
{
	cmdUnprotect();
	_tprintf(TEXT("Uninstalling RPCFW ...\n"));

	deleteFileFromSysfolder(RPC_FW_DLL_NAME);
	deleteFileFromSysfolder(RPC_MESSAGES_DLL_NAME);

	if (deleteEventSource())
	{
		_tprintf(TEXT("Event Log successfully removed...\n"));
	}
	else
	{
		_tprintf(TEXT("deleteEventSource failed: %d \n"), GetLastError());
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	_tprintf(TEXT("rpcFwMannager started...\n"));

	if (argc > 1)
	{
		std::basic_string<TCHAR> cmmd(argv[1]);

		if (cmmd.find(_T("/uninstall")) != std::string::npos)
		{
			cmdUninstall();
		}
		else if (cmmd.find(_T("/unprotect")) != std::string::npos)
		{
			cmdUnprotect();
		}
		else if (cmmd.find(_T("/update")) != std::string::npos) 
		{
			cmdUpdate();
			WaitForSingleObject(globalUnprotectlEvent, 1000);
		}
		else if (cmmd.find(_T("/install")) != std::string::npos)
		{
			cmdInstall();
		}
		else if (cmmd.find(_T("/pid")) != std::string::npos)
		{
			cmdPid(argc,  argv);
			WaitForSingleObject(globalUnprotectlEvent, 1000);
		}
		else if (cmmd.find(_T("/process")) != std::string::npos)
		{
			cmdProcess(argc, argv);
			WaitForSingleObject(globalUnprotectlEvent, 1000);
		}
		else
		{
			getHelp();
		}
	}
	else
	{
		getHelp();
	}
	return 0;
}
