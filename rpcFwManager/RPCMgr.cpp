// RPCrawler.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <optional>

#include "stdafx.h"
#include "rpcfilters.h"
#include <algorithm>

HANDLE globalMappedMemory = nullptr;
HANDLE globalUnprotectlEvent = nullptr;

enum class eventSignal {signalSetEvent, signalResetEvent};

typedef std::vector<std::pair<DWORD, std::wstring>> ProcVector;

CHAR configBuf[MEM_BUF_SIZE];

std::tuple<size_t, size_t, bool> getConfigOffsets(std::string confStr)
{
	size_t start_pos = confStr.find("!start!");
	size_t end_pos = confStr.find("!end!");

	if (start_pos == std::string::npos || end_pos == std::string::npos)
	{
		_tprintf(_T("Error reading start or end markers"));
		return std::make_tuple(0, 0, false);
	}
	start_pos += 7;

	return std::make_tuple(start_pos, end_pos, true);
}

std::wstring StringToWString(const std::string& s)
{
	std::wstring temp(s.length(), L' ');
	std::copy(s.begin(), s.end(), temp.begin());
	return temp;
}

std::wstring extractKeyValueFromConfigLineInner(const std::wstring& confLine, const std::wstring& key)
{
	const size_t keyOffset = confLine.find(key);

	if (keyOffset == std::string::npos) return _T("\0");

	const size_t nextKeyOffset = confLine.find(_T(" "), keyOffset + 1);

	if (nextKeyOffset == std::string::npos) return _T("\0");

	std::wstring val = confLine.substr(keyOffset + key.size(), nextKeyOffset - keyOffset - key.size());

	return val;
}

std::wstring extractKeyValueFromConfigLine(const std::wstring& confLine, const std::wstring& key)
{
	std::wstring fixedConfLine = confLine;

	std::size_t newLinePos = fixedConfLine.rfind(_T("\n"));
	std::size_t carrigeReturnPos = fixedConfLine.rfind(_T("\r"));


	//std::basic_string<wchar_t>::replace(fixedConfLine.begin(), fixedConfLine.end(), _T("\r"), _T(" "));
	if (newLinePos != std::wstring::npos) fixedConfLine.replace(fixedConfLine.rfind(_T("\n")), 1, _T(" "));
	if (carrigeReturnPos != std::wstring::npos) fixedConfLine.replace(fixedConfLine.rfind(_T("\r")), 1, _T(" "));
	
	fixedConfLine.replace(fixedConfLine.size() - 1, 1, _T(" "));

	return extractKeyValueFromConfigLineInner(fixedConfLine, key);
}

UUIDFilter extractUUIDFilterFromConfigLine(const std::wstring& confLine)
{
	std::wstring uuid = extractKeyValueFromConfigLine(confLine, _T("uuid:"));

	std::transform(uuid.begin(), uuid.end(), uuid.begin(), ::tolower);

	return uuid.empty() ? UUIDFilter{} : UUIDFilter{ uuid };
}

AddressFilter extractAddressFromConfigLine(const std::wstring& confLine)
{
	const std::wstring address = extractKeyValueFromConfigLine(confLine, _T("addr:"));

	return address.empty() ? AddressFilter{} : AddressFilter{ address };
}

OpNumFilter extractOpNumFilterFromConfigLine(const std::wstring& confLine)
{
	const std::wstring opnumString = extractKeyValueFromConfigLine(confLine, _T("opnum:"));

	if (opnumString.empty())
	{
		return {};
	}

	try {
		return std::stoi(opnumString);
	}
	catch (const std::invalid_argument&) {
		return {};
	}
}

bool extractActionFromConfigLine(const std::wstring& confLine)
{
	std::wstring action = extractKeyValueFromConfigLine(confLine, _T("action:"));

	return action.find(_T("block")) == std::string::npos;
}

bool extractAuditFromConfigLine(const std::wstring& confLine)
{
	std::wstring audit = extractKeyValueFromConfigLine(confLine, _T("audit:"));

	return audit.find(_T("true")) != std::string::npos;
}

RpcCallPolicy extractPolicyFromConfigLine(const std::wstring& confLine)
{
	return RpcCallPolicy
	{
		.allow = extractActionFromConfigLine(confLine),
		.audit = extractAuditFromConfigLine(confLine),
	};
}

void concatArguments(int argc, wchar_t* argv[], wchar_t command[])
{
	_tcscpy_s(command, MAX_PATH *2, argv[0]);
	
	for (int i = 1; i < argc; i++)
	{
		_tcscat_s(command, MAX_PATH * 2, TEXT(" "));
		_tcscat_s(command, MAX_PATH * 2, argv[i]);
	}

	_tcscat_s(command, MAX_PATH * 2, TEXT(" /elevated"));
}

ProcVector getRelevantProcVector(DWORD pid, std::wstring &pName)
{
	ProcVector procVector;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bool bProcess = Process32FirstW(hTool32, &pe32);

	if (bProcess == true) {
		while ((Process32Next(hTool32, &pe32)) == TRUE) 
		{
			if (!pName.empty() && compareStringsCaseinsensitive(pe32.szExeFile,(wchar_t*)pName.c_str()))
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

void crawlProcesses(DWORD pid, std::wstring &pName) 
{
	ProcVector procToHook = getRelevantProcVector(pid, pName);

	unsigned int i;
	size_t vSize = procToHook.size();
	for (i = 0; i < vSize; i++)
	{
		DWORD pid = procToHook[i].first;
		std::wstring procName = procToHook[i].second;

		_tprintf(TEXT("Protecting %d : %s\n"),pid,procName.c_str());
		classicHookRPCProcesses(pid, (wchar_t*)RPC_FW_DLL_NAME);
	}
}

void crawlProcesses(DWORD pid)
{
	std::wstring noProcName;
	crawlProcesses(pid, noProcName);
}

void getHelp()
{
	_tprintf(TEXT("Usage: rpcFwManager /<Command> [options] \n\n"));
	_tprintf(TEXT("command:\n"));
	_tprintf(TEXT("----------\n"));
	_tprintf(TEXT("install\t\t - configure EventLogs, auditing, put DLLs in the %%SystemRoot%%\\system32 folder.\n"));
	_tprintf(TEXT("uninstall\t - undo installation changes.\n"));
	_tprintf(TEXT("protect [options/pid/process]\t- Apply RPC protections according to the configuration file.\n"));
	_tprintf(TEXT("\tpid <pid>\t- Protect specified process ID with RPCFWP (no pid protects ALL processes!).\n"));
	_tprintf(TEXT("\tprocess <name>\t- Protect specified process by name with RPCFWP (no name protects ALL processes!).\n"));
	_tprintf(TEXT("unprotect\t - Remove protections.\n"));
	_tprintf(TEXT("update\t\t - Notify rpcFirewall.dll on configuration changes.\n"));
	_tprintf(TEXT("\noptions:\n"));
	_tprintf(TEXT("--------------\n"));
	_tprintf(TEXT("fw: apply command for RPC Firewall only (excluding <process/pid>).\n"));
	_tprintf(TEXT("flt: apply command for RPC Filters only (excluding <process/pid>).\n"));
	_tprintf(TEXT("all: apply command for RPC Firewall & Filters (excluding <process/pid>).\n"));
}

void deleteFileFromSysfolder(std::wstring fileName)
{

	wchar_t  destPath[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetSystemDirectory(destPath, INFO_BUFFER_SIZE))
	{
		_tprintf(TEXT("ERROR: Couldn't get the system directory [%d].\n"), GetLastError());
		return;
	}

	std::wstring destPathStr = destPath;
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

void writeFileToSysfolder(const std::wstring& sourcePath, const std::wstring& sourceFileName)
{
	wchar_t  destPath[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetSystemDirectory(destPath, INFO_BUFFER_SIZE))
	{
		_tprintf(TEXT("ERROR: Couldn't get the system directory [%d].\n"), GetLastError());
		return;
	}

	std::wstring destPathStr = destPath;
	destPathStr += TEXT("\\");
	destPathStr += sourceFileName;

	if (!CopyFile(sourcePath.c_str(), destPathStr.c_str(), false))
	{
		_tprintf(TEXT("ERROR: %s copy to system folder failed [%d].\n"), sourcePath.c_str(), GetLastError());
		return;
	}
}

std::wstring getFullPathOfFile(const std::wstring &filename)
{
	wchar_t  filePath[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetCurrentDirectory(bufCharCount, filePath))
	{
		_tprintf(TEXT("ERROR: Couldn't get the current directory [%d].\n"), GetLastError());
		return std::wstring();
	}

	return std::wstring(filePath) + _T("\\") + filename;
}

bool createSecurityAttributes(SECURITY_ATTRIBUTES * psa, PSECURITY_DESCRIPTOR psd)
{
	if (InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) != 0)
	{
		if (SetSecurityDescriptorDacl(psd, true, nullptr, false) != 0)
		{
			(*psa).nLength = sizeof(*psa);
			(*psa).lpSecurityDescriptor = psd;
			(*psa).bInheritHandle = false;

			return true;
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

	return false;
}

HANDLE createGlobalEvent(bool manualReset,bool initialState, wchar_t* eventName)
{
	HANDLE gEvent = nullptr;
	SECURITY_ATTRIBUTES sa = { 0 };
	PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	
	//TODO: return value instead of passing as ref
	if (createSecurityAttributes(&sa, psd))
	{
		gEvent = CreateEvent(&sa, manualReset, initialState, eventName);
		if (gEvent != nullptr)
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
	globalUnprotectlEvent = createGlobalEvent(true, false, (wchar_t*)GLOBAL_RPCFW_EVENT_UNPROTECT);
}

HANDLE mapNamedMemory()
{
	HANDLE hMapFile = nullptr;
	SECURITY_ATTRIBUTES sa = { 0 };
	PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

	if (createSecurityAttributes(&sa,psd))
	{
		hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, MEM_BUF_SIZE, GLOBAL_SHARED_MEMORY);
		if (hMapFile == nullptr)
		{
			_tprintf(TEXT("Error calling CreateFileMapping %d.\n"), GetLastError());
		}
	}

	LocalFree(psd);

	return hMapFile;
}

CHAR* readConfigFile(DWORD * bufLen)
{
	std::wstring cfgFwPath = getFullPathOfFile(std::wstring(CONF_FILE_NAME));
	HANDLE hFile = CreateFile(cfgFwPath.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("No configuration file found %d.\n"), GetLastError());
	}
	else if (!ReadFile(hFile,configBuf, MEM_BUF_SIZE - 1, bufLen,nullptr))
	{
		_tprintf(TEXT("ERROR: ReadFile %d.\n"), GetLastError());

	}

	return configBuf;
}

std::string addHeaderToBuffer(DWORD verNumber,CHAR* confBuf, DWORD bufSize)
{
	std::string strToHash = confBuf;
	strToHash.resize(bufSize);
	size_t hashValue = std::hash<std::string>{}(strToHash);

	std::string resultBuf = "ver:" + std::to_string(verNumber) +  " hash:" + std::to_string(hashValue) + "\r\n" + "!start!" + strToHash + "!end!";

	return resultBuf;
}

std::string extractKeyValueFromConfig(std::string confLine, std::string key)
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

		if (globalMappedMemory == nullptr)
		{
			std::quick_exit(-1);
		}

		pBuf = (CHAR*)MapViewOfFile(globalMappedMemory, FILE_MAP_ALL_ACCESS, 0, 0, MEM_BUF_SIZE);
		if (pBuf == nullptr)
		{
			_tprintf(TEXT("Error calling MapViewOfFile %d.\n"), GetLastError());
			CloseHandle(globalMappedMemory);
			std::quick_exit(-1);
		}
		
		DWORD verNumber = getConfigVersionNumber(pBuf);
		std::string confBufHashed = addHeaderToBuffer(verNumber + 1,confBuf, bytesRead);

		memset(pBuf, '\0', MEM_BUF_SIZE);
		CopyMemory((PVOID)pBuf, confBufHashed.c_str(), bytesRead + confBufHashed.length());
	}
}

void sendSignalToGlobalEvent(wchar_t* globalEventName, eventSignal eSig)
{
	HANDLE hEvent = createGlobalEvent(true, false, globalEventName);
	if (hEvent == nullptr)
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

void runCommandBasedOnParam(std::wstring &param, void funcFilter(void), void funcFireWall(void), std::wstring &errMsg)
{
	if (param.empty())
	{
		funcFilter();
		funcFireWall();
	}
	else
	{
		if ((param.find(_T("all")) != std::string::npos) || (param.find(_T("flt")) != std::string::npos))
		{
			funcFilter();
		}
		else if ((param.find(_T("all")) != std::string::npos) || (param.find(_T("fw")) != std::string::npos))
		{
			funcFireWall();
		}
		else
		{
			_tprintf(errMsg.c_str());
		}
	}
}

void cmdUpdateRPCFW()
{
	readConfigAndMapToMemory();
	WaitForSingleObject(globalUnprotectlEvent, 1000);
}

void cmdUnprotectRPCFLT()
{
	_tprintf(_T("disabling RPCFLT...\n"));
	if (!setSecurityPrivilege(_T("SeSecurityPrivilege")))
	{
		_tprintf(_T("Error: could not obtain SeSecurityPrivilege.\n"));
		return;
	}
	deleteAllRPCFilters();
}

void createRPCFiltersFromConfiguration()
{
	DWORD bytesRead = 0;
	std::string confBuf(readConfigFile(&bytesRead));

	unsigned int lineNum = 0;

	if (bytesRead > 0)
	{
		std::stringstream configStream(confBuf);
		std::wstring confLineString;
		char configLine[256];

		configLinesVector confLines;

		while (configStream.getline(configLine, 256))
		{
			confLineString = StringToWString(configLine);
			confLineString += L" ";
			LineConfig lineConfig = {};

			lineConfig.opnum = extractOpNumFilterFromConfigLine(confLineString);
			lineConfig.uuid = extractUUIDFilterFromConfigLine(confLineString);
			lineConfig.source_addr = extractAddressFromConfigLine(confLineString);
			lineConfig.policy = extractPolicyFromConfigLine(confLineString);

			confLines.push_back(std::make_pair(confLineString, lineConfig));
		}

		createRPCFilterFromTextLines(confLines);
	}
}

void recreateRPCFilters()
{
	cmdUnprotectRPCFLT();
	createRPCFiltersFromConfiguration();
}

void cmdProtectRPCFLT()
{
	recreateRPCFilters();
}

void cmdUpdateRPCFLT()
{
	recreateRPCFilters();
}

void cmdUpdate(std::wstring& param)
{
	std::wstring errMsg = _T("usage: /update <fw/flt/all>\n");
	runCommandBasedOnParam(param, cmdUpdateRPCFLT, cmdUpdateRPCFW, errMsg);
}

void cmdPid(int procNum)
{
	elevateCurrentProcessToSystem();
	createAllGloblEvents();
	readConfigAndMapToMemory();

	if (procNum > 0)
	{
		_tprintf(TEXT("Enabling RPCFW for process : %d\n"), procNum);
		crawlProcesses(procNum);
	}
	else
	{
		_tprintf(TEXT("Enabling RPCFW for ALL processes\n"));
		crawlProcesses(0);
	}
}

void cmdUnprotectRPCFW()
{
	_tprintf(TEXT("Dispatching unprotect request...\n"));
	sendSignalToGlobalEvent((wchar_t*)GLOBAL_RPCFW_EVENT_UNPROTECT, eventSignal::signalSetEvent);
}

void cmdUnprotect(std::wstring& param)
{
	std::wstring errMsg = _T("usage: /unprotect <fw/flt/all>\n");
	runCommandBasedOnParam(param, cmdUnprotectRPCFLT , cmdUnprotectRPCFW, errMsg);
}

void cmdInstallRPCFLT()
{
	_tprintf(TEXT("installing RPCFLT Provider...\n"));
	installRPCFWProvider();
	_tprintf(TEXT("enabling RPCFLT...\n"));
	if (!setSecurityPrivilege(TEXT("SeSecurityPrivilege")))
	{
		_tprintf(TEXT("Error: could not obtain SeSecurityPrivilege.\n"));
		return;
	}
	enableAuditingForRPCFilters();
}

void cmdInstallRPCFW()
{
	_tprintf(TEXT("installing RPCFW...\n"));
	elevateCurrentProcessToSystem();
	
	writeFileToSysfolder(getFullPathOfFile(std::wstring(RPC_FW_DLL_NAME)), RPC_FW_DLL_NAME);
	writeFileToSysfolder(getFullPathOfFile(std::wstring(RPC_MESSAGES_DLL_NAME)), RPC_MESSAGES_DLL_NAME);

	addEventSource();
}

void cmdProtectRPCFW()
{
	_tprintf(TEXT("Enabling RPCFW for ALL processes\n"));
	crawlProcesses(0);
}

void cmdProtect(std::wstring &param)
{
	std::wstring errMsg = _T("usage: /protect <fw/flt/all>\n");
	runCommandBasedOnParam(param, cmdProtectRPCFLT, cmdProtectRPCFW, errMsg);
}

void cmdProcess(std::wstring &processName)
{
	createAllGloblEvents();
	elevateCurrentProcessToSystem();
	readConfigAndMapToMemory();
	if (!processName.empty())
	{
		_tprintf(TEXT("Enabling RPCFW for process : %s\n"), processName.c_str());
		crawlProcesses(17, processName);
	}
	else
	{
		_tprintf(TEXT("Enabling RPCFW for ALL processes\n"));
		crawlProcesses(0, processName);
	}
}

void cmdUninstallRPCFW()
{
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

void cmdUninstallRPCFLT()
{
	cmdUnprotectRPCFLT();
	disableAuditingForRPCFilters();
}

void cmdUninstall(std::wstring &param)
{
	std::wstring errMsg = _T("usage: /uninstall <fw/flt/all>\n");
	runCommandBasedOnParam(param, cmdUninstallRPCFLT, cmdUninstallRPCFW, errMsg);
}

void cmdInstall(std::wstring &param)
{
	std::wstring errMsg = _T("usage: /install <fw/flt/all>\n");
	runCommandBasedOnParam(param, cmdInstallRPCFLT, cmdInstallRPCFW, errMsg);
}

int _tmain(int argc, wchar_t* argv[])
{
	_tprintf(TEXT("rpcFwMannager started...\n"));

	if (argc > 1)
	{
		std::wstring cmmd(argv[1]);
		std::wstring param;
		if (argc > 2)
		{
			param = std::wstring(argv[2]);
		}

		if (cmmd.find(_T("/uninstall")) != std::string::npos)
		{
			cmdUninstall(param);
		}
		else if (cmmd.find(_T("/unprotect")) != std::string::npos)
		{
			cmdUnprotect(param);
		}
		else if (cmmd.find(_T("/protect")) != std::string::npos)
		{
			if (param.find(_T("pid")) != std::string::npos)
			{
				if (argc > 3) {
					int procNum = std::stoi((std::wstring)argv[3], nullptr, 10);
					cmdPid(procNum);
				}
				else
				{
					cmdPid(0);
				}		
			}
			else if (param.find(_T("process")) != std::string::npos)
			{
				std::wstring processName;
				if (argc > 3) {
					processName = argv[3];
				}
				cmdProcess(processName);
			}
			else
			{
				cmdProtect(param);
			}
			WaitForSingleObject(globalUnprotectlEvent, 1000);
		}
		else if (cmmd.find(_T("/update")) != std::string::npos) 
		{
			cmdUpdate(param);
		}
		else if (cmmd.find(_T("/install")) != std::string::npos)
		{
			cmdInstall(param);
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
