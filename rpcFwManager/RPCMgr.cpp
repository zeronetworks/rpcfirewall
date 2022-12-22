// RPCrawler.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <optional>
#include <fstream>


#include "stdafx.h"
#include "rpcfilters.h"
#include <algorithm>
#include "common.h"
#include "service.h"

enum class eventSignal {signalSetEvent, signalResetEvent};

std::wstring extractKeyValueFromConfigLineInner(const std::wstring& confLine, const std::wstring& key)
{
	const size_t keyOffset = confLine.find(key);

	if (keyOffset == std::string::npos) return _T("\0");

	const size_t nextKeyOffset = confLine.find(L' ', keyOffset + 1);

	if (nextKeyOffset == std::string::npos) return _T("\0");

	std::wstring val = confLine.substr(keyOffset + key.size(), nextKeyOffset - keyOffset - key.size());

	return val;
}

std::wstring extractKeyValueFromConfigLine(const std::wstring& confLine, const std::wstring& key)
{
	std::wstring fixedConfLine = confLine;

	std::size_t newLinePos = fixedConfLine.rfind(L'\n');
	std::size_t carriageReturnPos = fixedConfLine.rfind(L'\r');

	//std::basic_string<wchar_t>::replace(fixedConfLine.begin(), fixedConfLine.end(), _T("\r"), _T(" "));
	if (newLinePos != std::wstring::npos) fixedConfLine.replace(fixedConfLine.rfind(L'\n'), 1, _T(" "));
	if (carriageReturnPos != std::wstring::npos) fixedConfLine.replace(fixedConfLine.rfind(L'\r'), 1, _T(" "));

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

SIDFilter extractSIDFromConfigLine(const std::wstring& confLine)
{
	const std::wstring sidString = extractKeyValueFromConfigLine(confLine, _T("sid:"));

	return sidString.empty() ? SIDFilter{} : SIDFilter{ sidString};
}

bool extractActionFromConfigLine(const std::wstring& confLine)
{
	std::wstring action = extractKeyValueFromConfigLine(confLine, _T("action:"));

	return action.find(_T("block")) == std::string::npos;
}

protocolFilter extractProtoclFromConfigLine(const std::wstring& confLine)
{
	const std::wstring protocol = extractKeyValueFromConfigLine(confLine, _T("prot"));

	return protocol.empty() ? protocolFilter{} : protocolFilter{protocol};
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

bool checkIfFilterConfigLine(const std::wstring& confLine)
{
	std::wstring flt = extractKeyValueFromConfigLine(confLine, _T("flt:"));

	return !flt.empty();

}

void concatArguments(int argc, wchar_t* argv[], wchar_t command[])
{
	_tcscpy_s(command, MAX_PATH * 2, argv[0]);

	for (int i = 1; i < argc; i++)
	{
		_tcscat_s(command, MAX_PATH * 2, TEXT(" "));
		_tcscat_s(command, MAX_PATH * 2, argv[i]);
	}

	_tcscat_s(command, MAX_PATH * 2, TEXT(" /elevated"));
}

void getHelp()
{
	_tprintf(TEXT("Usage: rpcFwManager /<Command> [options] \n\n"));
	_tprintf(TEXT("command:\n"));
	_tprintf(TEXT("----------\n"));
	_tprintf(TEXT("install\t\t - configure EventLogs, auditing, put DLLs in the %%SystemRoot%%\\system32 folder.\n"));
	_tprintf(TEXT("uninstall\t - undo installation changes.\n"));
	_tprintf(TEXT("start [options/pid/process]\t- Apply RPC protections according to the configuration file.\n"));
	_tprintf(TEXT("\tpid <pid>\t- Protect specified process ID with RPCFWP (no pid protects ALL processes!).\n"));
	_tprintf(TEXT("\tprocess <name>\t- Protect specified process by name with RPCFWP (no name protects ALL processes!).\n"));
	_tprintf(TEXT("stop\t - Remove protections.\n"));
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
	// DWORD  bufCharCount = INFO_BUFFER_SIZE;

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


bool checkIfFileInSysFolder(const std::wstring& sourceFileName)
{
	wchar_t  destPath[INFO_BUFFER_SIZE];
	// DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetSystemDirectory(destPath, INFO_BUFFER_SIZE))
	{
		_tprintf(TEXT("ERROR: Couldn't get the system directory [%d].\n"), GetLastError());
		return false;
	}

	std::wstring destPathStr = destPath;
	destPathStr += TEXT("\\");
	destPathStr += sourceFileName;

	std::ifstream ifile;
	ifile.open(destPathStr.c_str());
	
	if (ifile)
	{
		ifile.close();
		return true;
	}
	ifile.close();
	return false;

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
	if (param.empty() || (param.find(_T("all")) != std::string::npos))
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
	WaitForSingleObject(globalUnprotectEvent, 1000);
}

void cmdUnprotectRPCFLT()
{
	_tprintf(_T("Removing RPC Filters...\n"));
	if (!setSecurityPrivilege(_T("SeSecurityPrivilege")))
	{
		_tprintf(_T("Error: could not obtain SeSecurityPrivilege.\n"));
		return;
	}
	deleteAllRPCFilters();
}

void createRPCFiltersFromConfiguration()
{
	_tprintf(_T("Creating RPC Filters...\n"));
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

			if (checkIfFilterConfigLine(confLineString))
			{
				lineConfig.opnum = extractOpNumFilterFromConfigLine(confLineString);
				lineConfig.uuid = extractUUIDFilterFromConfigLine(confLineString);
				lineConfig.source_addr = extractAddressFromConfigLine(confLineString);
				lineConfig.policy = extractPolicyFromConfigLine(confLineString);
				lineConfig.sid = extractSIDFromConfigLine(confLineString);
				lineConfig.protocol = extractProtoclFromConfigLine(confLineString);

				confLines.push_back(std::make_pair(confLineString, lineConfig));
			}
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
	createAllGlobalEvents();
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
	serviceStop();
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

	serviceInstall(SERVICE_DEMAND_START);
}

void cmdProtectRPCFW()
{
	serviceMakeAutostart();
	serviceStart();
}

void cmdProtect(std::wstring &param)
{
	std::wstring errMsg = _T("usage: /protect <fw/flt/all>\n");
	runCommandBasedOnParam(param, cmdProtectRPCFLT, cmdProtectRPCFW, errMsg);
}

void cmdStatusRPCFLT()
{
	outputMessage(L"\n----------------------");
	outputMessage(L"RPC Filter status:");
	outputMessage(L"----------------------");
	
	/*bool isInstalled = isProviderInstalled();
	std::wstring providerStat = isInstalled  ? L"Provider installed" : L"Provider not installed";
	outputMessage(providerStat.c_str());*/
	
	outputMessage(L"\n\tinstallation:");
	outputMessage(L"\t----------------------");

	std::wstring auditing = isAuditingEnabledForRPCFilters() ? L"\tAuditing enabled" : L"\tAuditing not enabled";
	outputMessage(auditing.c_str());
	
	outputMessage(L"\n\tFilters:");
	outputMessage(L"\t----------------------");
	printAllRPCFilters();
		
}

void cmdStatusRPCFW()
{
	elevateCurrentProcessToSystem();
	outputMessage(L"\n----------------------");
	outputMessage(L"RPC Firewall status:");
	outputMessage(L"----------------------");
	
	std::wstringstream RPCFWFileState;
	RPCFWFileState << L"\t" << RPC_FW_DLL_NAME << (checkIfFileInSysFolder(RPC_FW_DLL_NAME) ? L" installed" : L" not installed");
	std::wstringstream RPCMSGFileState;
	RPCMSGFileState << L"\t" << RPC_MESSAGES_DLL_NAME << (checkIfFileInSysFolder(RPC_MESSAGES_DLL_NAME) ? L" installed" : L" not installed");
	std::wstringstream serviceInstalledState;
	serviceInstalledState << L"\t" << L"RPC Firewall Service" << (isServiceInstalled() ? L" installed" : L" not installed");
	std::wstringstream eventState;
	eventState << L"\t" << L"RPC Firewall Event" << (checkIfEventConfiguredInReg() ? L" configured" : L" not configured");

	outputMessage(RPCFWFileState.str().c_str());
	outputMessage(RPCMSGFileState.str().c_str());
	outputMessage(serviceInstalledState.str().c_str());
	outputMessage(eventState.str().c_str());
	if (isServiceInstalled()) printServiceState();

	outputMessage(L"\n");
	printProcessesWithRPCFW();

	outputMessage(L"\n\tconfiguration:");
	outputMessage(L"\t----------------------");
	printMappedMemoryConfiguration();

}

void cmdStatus(std::wstring& param)
{
	std::wstring errMsg = _T("usage: /status <fw/flt/all>\n");
	runCommandBasedOnParam(param, cmdStatusRPCFLT, cmdStatusRPCFW, errMsg);
}

void cmdProcess(std::wstring &processName)
{
	createAllGlobalEvents();
	elevateCurrentProcessToSystem();
	readConfigAndMapToMemory();
	if (!processName.empty())
	{
		std::wstring msg = L"Enabling RPCFW for process :";
		msg += processName;
		outputMessage(msg.c_str());
		crawlProcesses(17, processName);
	}
	else
	{
		outputMessage(TEXT("Enabling RPCFW for ALL processes"));
		crawlProcesses(0, processName);
	}

	WaitForSingleObject(globalUnprotectEvent, 1000);
}

void cmdUninstallRPCFW()
{
	outputMessage(TEXT("Uninstalling RPCFW ..."));
	elevateCurrentProcessToSystem();
	serviceStop();
	serviceMakeManual();

	serviceUninstall();

	deleteFileFromSysfolder(RPC_FW_DLL_NAME);
	deleteFileFromSysfolder(RPC_MESSAGES_DLL_NAME);

	if (deleteEventSource())
	{
		outputMessage(TEXT("Event Log successfully removed..."));
	}
	else
	{
		outputMessage(TEXT("deleteEventSource failed: %d \n"), GetLastError());
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
	interactive = !setupService();

	if (interactive)
	{
		_tprintf(TEXT("RPCFW Manager started manually...\n"));
	}

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
		else if (cmmd.find(_T("/stop")) != std::string::npos)
		{
			cmdUnprotect(param);
		}
		else if (cmmd.find(_T("/start")) != std::string::npos)
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
			WaitForSingleObject(globalUnprotectEvent, 1000);
		}
		else if (cmmd.find(_T("/update")) != std::string::npos) 
		{
			cmdUpdate(param);
		}
		else if (cmmd.find(_T("/install")) != std::string::npos)
		{
			cmdInstall(param);
		}
		else if (cmmd.find(_T("/status")) != std::string::npos)
		{
			cmdStatus(param);
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
