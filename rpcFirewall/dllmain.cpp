// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <detours.h>
#include <string>
#include <sstream>
#include <rpc.h>
#include <rpcndr.h>
#include <rpcMessages.h>
#include <tchar.h>
#include <tuple>
#include <vector>
#include <type_traits>
#include <algorithm>
#include "config.hpp"

HMODULE myhModule;

DoubleBufferedConfig config;
std::string privateConfigBuffer = {};

CHAR* mappedBuf = NULL;
bool AuditOnly = false;
bool detouredFunctions = false;
bool verbose = true;
#define MUTEX_TIMEOUT_MS 15000
wchar_t myProcessName[MAX_PATH];
wchar_t myProcessID[16] = { 0 };

HANDLE uninstallEvent = NULL;
HANDLE configurationUpdatedEvent = NULL;
HANDLE managerDoneEvent = NULL;
HANDLE hConfigurationMapFile = NULL;

DWORD configurationVersion = 0;

template<typename T, typename U>
std::basic_string<T> to_tstring(U arg)
{
	if constexpr (std::is_same_v<T, char>)
	{
		return std::to_string(arg);
	}
	else if constexpr (std::is_same_v<T, wchar_t>)
	{
		return std::to_wstring(arg);
	}
	else
	{
		static_assert(false);
	}
}

static long (WINAPI* realNdrStubCall2)(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase) = NdrStubCall2;
long WINAPI detouredNdrStubCall2(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase);

static void (WINAPI* realNdrServerCallAll)(PRPC_MESSAGE pRpcMsg) = NdrServerCallAll;
void WINAPI detouredNdrServerCallAll(PRPC_MESSAGE pRpcMsg);

static void (WINAPI* realNdrAsyncServerCall)(PRPC_MESSAGE pRpcMsg) = NdrAsyncServerCall;
void WINAPI detouredNdrAsyncServerCall(PRPC_MESSAGE pRpcMsg);

static void (WINAPI* realNdr64AsyncServerCallAll)(PRPC_MESSAGE pRpcMsg) = Ndr64AsyncServerCallAll;
void WINAPI detouredNdr64AsyncServerCallAll(PRPC_MESSAGE pRpcMsg);

static void (WINAPI* realNdr64AsyncServerCall64)(PRPC_MESSAGE pRpcMsg) = Ndr64AsyncServerCall64;
void WINAPI detouredNdr64AsyncServerCall64(PRPC_MESSAGE pRpcMsg);

static void (WINAPI* realNdrServerCallNdr64)(PRPC_MESSAGE pRpcMsg) = NdrServerCallNdr64;
void WINAPI detouredNdrServerCallNdr64(PRPC_MESSAGE pRpcMsg);

#define WRITE_DEBUG_MSG(msg) \
	if (verbose) \
		writeDebugOutputWithPID(msg)

#define WRITE_DEBUG_MSG_WITH_STATUS(msg,status) \
	if (verbose) \
		writeDebugOutputWithPIDWithStatusMessage(msg,status)

#define WRITE_DEBUG_MSG_WITH_ERROR_MSG(msg,errMsgPtr) \
	if (verbose) \
		writeDebugOutputWithPIDWithErrorMessage(msg,errMsgPtr)

#define WRITE_DEBUG_MSG_WITH_GETLASTERROR(msg) \
	if (verbose) \
		writeDebugOutputWithPIDGetLastError(msg)

void writeDebugOutputWithPID(const std::wstring& dbgMsg)
{
	OutputDebugString(dbgMsg.c_str());
}

void writeDebugOutputWithPIDWithStatusMessage(const std::wstring& dbgMsg, DWORD status)
{
	std::wstring errMsg = dbgMsg + _T(" : ") + std::to_wstring(status);
	writeDebugOutputWithPID(errMsg);
}

void writeDebugOutputWithPIDWithErrorMessage(const std::wstring& dbgMsg, wchar_t* errMsgPtr)
{
	if (verbose)
	{
		wchar_t pidBuf[32];
		_stprintf_s(pidBuf, _T("%d"), GetCurrentProcessId());

		std::wstring finalMessage = pidBuf;
		std::wstring errMsg = errMsgPtr;

		finalMessage += TEXT(" - ");
		finalMessage += dbgMsg;
		finalMessage += TEXT(" : ");
		finalMessage += errMsg;

		writeDebugOutputWithPID(finalMessage.c_str());
	}
}

void writeDebugOutputWithPIDGetLastError(const std::wstring& dbgMsg)
{
	if (verbose)
	{

		wchar_t errBuf[32];
		_stprintf_s(errBuf, _T("%d"), GetLastError());

		std::wstring finalMessage = _T("");
		std::wstring errMsg = errBuf;

		finalMessage += dbgMsg;
		finalMessage += TEXT(" : ");
		finalMessage += errMsg;
		writeDebugOutputWithPID(finalMessage.c_str());
	}
}

void unloadSelf()
{
	FreeLibraryAndExitThread(myhModule, 0);
}

bool checkIfReleventRegisteredEndpointsForProcess()
{
	bool relevantEndpoint = false;
	RPC_BINDING_VECTOR* binding_vector;
	RPC_WSTR szStringBinding;
	std::wstring allEndpoints = _T("Endpoint LIST:");
	std::wstring singleEndpoint;

	RPC_STATUS status = RpcServerInqBindings(&binding_vector);
	if (status == RPC_S_OK)
	{
		for (unsigned long i = 0; i < binding_vector->Count; i++)
		{
			status = RpcBindingToStringBinding(binding_vector->BindingH[i], &szStringBinding);
			if (status == RPC_S_OK)
			{
				singleEndpoint = (wchar_t*)szStringBinding;
				if (_tcsstr(singleEndpoint.c_str(), _T("ncalrpc")) == NULL)
				{
					relevantEndpoint = true;
				}
				allEndpoints += singleEndpoint + _T(",");
			}
			RpcStringFree(&szStringBinding);
		}

		WRITE_DEBUG_MSG(allEndpoints);

		if (RpcBindingVectorFree(&binding_vector) != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("RpcBindingVectorFree failed"));
		}
	}
	else
	{
		WRITE_DEBUG_MSG(TEXT("No registered endpoints? still using RPC firewall..."));
		relevantEndpoint = true;
	}

	return relevantEndpoint;
}

bool checkIfRegisteredUUIDsForProcess()
{
	RPC_IF_ID_VECTOR* if_id_vector;
	RPC_WSTR szStringUuid;
	std::wstring allUUIDs = _T("UUID LIST:");
	std::wstring singleUUID;

	RPC_STATUS status = RpcMgmtInqIfIds(NULL, &if_id_vector);
	if (status == RPC_S_OK)
	{
		for (unsigned long i = 0; i < if_id_vector->Count; i++)
		{
			status = UuidToString(&(if_id_vector->IfId[i]->Uuid), &szStringUuid);
			if (status == RPC_S_OK)
			{
				singleUUID = (wchar_t*)szStringUuid;
				allUUIDs += singleUUID + _T(",");
			}
			RpcStringFree(&szStringUuid);
		}
		
		WRITE_DEBUG_MSG(allUUIDs);

		if (RpcIfIdVectorFree(&if_id_vector) != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("RpcIfIdVectorFree failed"));
		}
	}
	else
	{
		WRITE_DEBUG_MSG(TEXT("No registered interfaces, unloading firewall..."));
		return false;
	}

	return true;
}

std::wstring convertAuthLevelToString(unsigned long authLvl)
{
	switch (authLvl)
	{
	case RPC_C_AUTHN_LEVEL_DEFAULT: return TEXT("DEFAULT");
	case RPC_C_AUTHN_LEVEL_NONE: return TEXT("NONE");
	case RPC_C_AUTHN_LEVEL_CONNECT: return TEXT("CONNECT");
	case RPC_C_AUTHN_LEVEL_CALL: return TEXT("CALL");
	case RPC_C_AUTHN_LEVEL_PKT: return TEXT("PKT");
	case RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: return TEXT("PKT_INTEGRITY");
	case RPC_C_AUTHN_LEVEL_PKT_PRIVACY: return TEXT("PKT_PRIVACY");
	}
	return TEXT("UNKNOWN");
}

std::wstring convertAuthSvcToString(unsigned long authSvc)
{
	switch (authSvc)
	{
	case RPC_C_AUTHN_DPA: return TEXT("DPA");
	case RPC_C_AUTHN_GSS_KERBEROS: return TEXT("KERBEROS");
	case RPC_C_AUTHN_GSS_NEGOTIATE: return TEXT("NEGOTIATE");
	case RPC_C_AUTHN_GSS_SCHANNEL: return TEXT("SCHANNEL");
	case RPC_C_AUTHN_MQ: return TEXT("MQ");
	case RPC_C_AUTHN_MSN: return TEXT("MSN");
	case RPC_C_AUTHN_WINNT: return TEXT("WINNT");
	case RPC_C_AUTHN_DCE_PRIVATE: return TEXT("DCE_PRIVATE");
	case RPC_C_AUTHN_DEC_PUBLIC: return TEXT("DCE_PUBLIC");
	}
	return TEXT("UNKNOWN");
}

std::tuple<size_t, size_t, bool> getConfigOffsets(std::string confStr)
{
	size_t start_pos = confStr.find("!start!");
	size_t end_pos = confStr.find("!end!");

	if (start_pos == std::string::npos || end_pos == std::string::npos)
	{
		WRITE_DEBUG_MSG(_T("Error reading start or end markers"));
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

std::wstring extractKeyValueFromConfigLineInner(const std::wstring& confLine, const std::wstring & key)
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

	fixedConfLine.replace(fixedConfLine.size() - 1, 1, _T(" "));

	return extractKeyValueFromConfigLineInner(fixedConfLine, key);
}

UUIDFilter extractUUIDFilterFromConfigLine(const std::wstring& confLine)
{
	const std::wstring uuid = extractKeyValueFromConfigLine(confLine, _T("uuid:"));

	return uuid.empty() ? UUIDFilter{} : UUIDFilter{ uuid };
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
		WRITE_DEBUG_MSG(_T("Invalid opnum provided: ") + opnumString);
		return {};
	}
}

AddressFilter extractAddressFromConfigLine(const std::wstring& confLine)
{
	const std::wstring address = extractKeyValueFromConfigLine(confLine, _T("addr:"));

	return address.empty() ? AddressFilter{} : AddressFilter{ address };
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

bool extractVerboseFromConfigLine(const std::wstring& confLine)
{
	std::wstring loc_verbose = extractKeyValueFromConfigLine(confLine, _T("verbose:"));

	return loc_verbose.find(_T("true")) != std::string::npos;
}

void loadPrivateBufferToPassiveVectorConfiguration()
{
	WRITE_DEBUG_MSG(StringToWString(privateConfigBuffer));

	auto markers = getConfigOffsets(privateConfigBuffer);
	size_t start_pos = std::get<0>(markers);
	size_t end_pos = std::get<1>(markers);

	std::string configurationOnly = privateConfigBuffer.substr(start_pos, end_pos - start_pos);

	std::basic_istringstream<wchar_t> configStream(StringToWString(configurationOnly));
	std::wstring confLineString;
	wchar_t configLine[256];

	size_t size = privateConfigBuffer.size() + 1;
	ConfigVector passiveConfigVector = {};

	if (size > 1)
	{
		while (configStream.getline(configLine, 256))
		{
			confLineString = configLine;
			confLineString += _T(" ");
			LineConfig lineConfig = {};

			lineConfig.uuid = extractUUIDFilterFromConfigLine(confLineString);
			lineConfig.opnum = extractOpNumFilterFromConfigLine(confLineString);
			lineConfig.source_addr = extractAddressFromConfigLine(confLineString);
			lineConfig.allow = extractActionFromConfigLine(confLineString);
			lineConfig.audit = extractAuditFromConfigLine(confLineString);
			lineConfig.verbose = extractVerboseFromConfigLine(confLineString);
			passiveConfigVector.push_back(lineConfig);
		}
	}

	config.setPassiveConfigurationVector(passiveConfigVector);
}

bool checkKeyValueInConfigLine(wchar_t* confLine, wchar_t* key,DWORD keySize, const std::wstring& value)
{
	std::wstring confString = confLine;
	confString += _T("");

	size_t keyOffset = confString.find(key);
	if (keyOffset == std::string::npos) return true;

	size_t keyEndOffset = confString.find(_T(" "), keyOffset);
	size_t configValueSize = keyEndOffset - keyOffset - keySize;
	
	if (configValueSize != value.size())
	{
		return false;
	}

	auto configValueStr = confString.substr(keyOffset + keySize, configValueSize);

	return compareStringsCaseinsensitive((wchar_t*)configValueStr.c_str(), (wchar_t*)value.c_str(), configValueSize);
}

bool checkAudit(wchar_t* confLine)
{
	return _tcsstr(confLine, TEXT("audit:true"));
}

bool checkUUID(const UUIDFilter& uuidFilter, const std::wstring& uuidString)
{
	if (!uuidFilter.has_value())
	{
		return true;
	}
	
	return uuidFilter.value().find(uuidString) != std::string::npos;
}

bool checkOpNum(const OpNumFilter& opNumFilter, const std::wstring& opNumString)
{
	if (!opNumFilter.has_value())
	{
		return true;
	}

	return opNumFilter == std::stoi(opNumString);
}

bool checkAddress(const AddressFilter& addrFilter, const std::wstring& srcAddr)
{
	if (!addrFilter.has_value())
	{
		return true;
	}
	
	return addrFilter == srcAddr;
}

std::pair<bool,bool> checkIfRPCCallFiltered(RpcEventParameters rpcEvent)
{
	const ConfigVector& configurationVector = config.getActiveConfigurationVector();

	bool UUIDMatch, AddressMatch, OpNumMatch, auditCall, filterCall = false;
	DWORD verboseCount = 0;

	for (const LineConfig& lc : configurationVector)
	{
		UUIDMatch = checkUUID(lc.uuid, rpcEvent.uuidString);
		AddressMatch = checkAddress(lc.source_addr, rpcEvent.sourceAddress);
		OpNumMatch = checkOpNum(lc.opnum, rpcEvent.OpNum);

		if (UUIDMatch && AddressMatch && OpNumMatch)
		{
			WRITE_DEBUG_MSG(_T("Rule Matched for RPC call."));
			auditCall = lc.audit;
			filterCall = !lc.allow;

			break;
		}
	}

	return std::make_pair(filterCall,auditCall);
}

void mappedBufferCopyToPrivateConfiguration()
{
	privateConfigBuffer = mappedBuf;
}

bool isNewVersion()
{
	size_t verLoc = privateConfigBuffer.find("ver:");
	if (verLoc == std::string::npos)
	{
		WRITE_DEBUG_MSG(_T("No version keyword found"));
		return false;
	}
	size_t verEndPos = privateConfigBuffer.find(" ") + 1;
	DWORD newVersion = std::stoi(privateConfigBuffer.substr(verLoc + 4, verEndPos - 5));
	
	if (newVersion > configurationVersion)
	{
		WRITE_DEBUG_MSG(_T("New configuration version detected."));
		configurationVersion = newVersion;
		return true;
	}

	return false;
}

bool isHashValid()
{
	bool validConfig = false;
	// Try and read buffer untill hash is valid
	size_t hashLoc = privateConfigBuffer.find("hash:");
	if (hashLoc == std::string::npos)
	{
		WRITE_DEBUG_MSG(_T("No hash keyword found"));
		return validConfig;
	}
	size_t hashEndPos = privateConfigBuffer.find("\r\n") + 1;
	size_t declaredHashVal;
	if (sscanf_s((privateConfigBuffer.substr(hashLoc + 5, hashEndPos - 6)).c_str(), "%zu", &declaredHashVal) == 0)
	{
		WRITE_DEBUG_MSG(_T("Error reading declared hash value!"));
		return validConfig;
	}

	auto markers = getConfigOffsets(privateConfigBuffer);
	if (!std::get<2>(markers))
	{
		return validConfig;
	}
	size_t start_pos = std::get<0>(markers);
	size_t end_pos = std::get<1>(markers);

	size_t calculatedHashValue = std::hash<std::string>{}(privateConfigBuffer.substr(start_pos,end_pos - start_pos));

	if (calculatedHashValue == declaredHashVal)
	{
		validConfig = true;
	}

	return validConfig;
}

bool checkIfVerbose()
{
	const ConfigVector& configurationVector = config.getActiveConfigurationVector();

	return std::any_of(configurationVector.begin(), configurationVector.end(), [](const LineConfig& lc) { return lc.verbose; });
}

void loadConfigurationFromMappedMemory()
{
	if (hConfigurationMapFile == NULL)
	{
		WRITE_DEBUG_MSG(_TEXT("Calling OpenFileMapping..."));
		hConfigurationMapFile = OpenFileMapping(FILE_MAP_READ, false, GLOBAL_SHARED_MEMORY);

		if (hConfigurationMapFile == NULL)
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Could not open configuration. Auditing only..."));
			AuditOnly = true;

			return;
		}
	}
	
	if (mappedBuf == NULL)
	{
		WRITE_DEBUG_MSG(_TEXT("Calling MapViewOfFile..."));
		mappedBuf = (CHAR*)MapViewOfFile(hConfigurationMapFile, FILE_MAP_READ, 0, 0, MEM_BUF_SIZE);

		if (mappedBuf == NULL)
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Error: Could not map view of file."));
			CloseHandle(hConfigurationMapFile);
			hConfigurationMapFile = NULL;

			return;
		}
	}

	for (int i = 0; i < 5; i++)
	{
		mappedBufferCopyToPrivateConfiguration();
		if (isHashValid())
		{
			if (isNewVersion())
			{
				loadPrivateBufferToPassiveVectorConfiguration();
				config.changeActiveConfigurationNumber();
				verbose = checkIfVerbose();
			}
			break;
		}
	}
}

void writeEventToDebugOutput(RpcEventParameters eventParams, bool allowCall)
{
	std::wstring dbgMsg = _T("");
	dbgMsg += TEXT("RPC Function ");
	if (allowCall)
	{
		dbgMsg += TEXT("Allowed,");
	}
	else
	{
		dbgMsg += TEXT("Blocked,");
	}
	dbgMsg += eventParams.functionName + _T(",") + eventParams.endpoint + _T(",") + eventParams.uuidString+ _T(",") + eventParams.protocol+ _T(",") + eventParams.sourceAddress+ _T(",") + eventParams.OpNum + _T(",") + eventParams.clientName + _T(",") + eventParams.authnLevel + _T(",") + eventParams.authnSvc;
	WRITE_DEBUG_MSG(dbgMsg);
}

void waitForFurtherInstructions()
{
	loadConfigurationFromMappedMemory();
	HANDLE uninstallEvent = OpenEvent(SYNCHRONIZE, false, GLOBAL_RPCFW_EVENT_UNPROTECT);

	if (uninstallEvent != NULL)
	{
		HANDLE allEvents[2];
		allEvents[0] = uninstallEvent;
		allEvents[1] = configurationUpdatedEvent;
		bool keepOnSpinning = true;

		while (keepOnSpinning)
		{
			DWORD dwWaitResult = WaitForSingleObject(uninstallEvent, 10000);
			//DWORD dwWaitResult = WaitForMultipleObjects(2, allEvents, false, INFINITE);
			switch (dwWaitResult) {
			case WAIT_OBJECT_0:
				WRITE_DEBUG_MSG(TEXT("Unprotect event..."));
				keepOnSpinning = false;
				break;
			case WAIT_TIMEOUT:
				loadConfigurationFromMappedMemory();
				break;
			default:
				keepOnSpinning = false;
				WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("ERROR from WaitForMultipleObjects"));
			}
		}
	}
	else
	{
		WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("OpenEvent failed, unloading firewall..."));
	}
	unloadSelf();
}

void mainStart()
{
	WRITE_DEBUG_MSG(TEXT("RPCFirewall DLL Loaded..."));
	if (!checkIfRegisteredUUIDsForProcess())
	{
		unloadSelf();
		return;
	}

	if (!checkIfReleventRegisteredEndpointsForProcess() && _tcsstr(myProcessName,_T("spoolsv.exe")) == NULL)
	{
		unloadSelf();
		return;
	}

	WRITE_DEBUG_MSG(TEXT("RPCFirewall confirmed relevant RPC server."));

	DisableThreadLibraryCalls(myhModule);
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	detouredFunctions = true;

	if (DetourAttach(&(PVOID&)realNdrStubCall2, detouredNdrStubCall2) != NO_ERROR)
	{
		WRITE_DEBUG_MSG(TEXT("DetourAttach error on NdrStubCall2"));
	}
	if (DetourAttach(&(PVOID&)realNdrServerCallAll, detouredNdrServerCallAll) != NO_ERROR)
	{
		WRITE_DEBUG_MSG(TEXT("DetourAttach error on NdrServerCallAll"));
	}
	if (DetourAttach(&(PVOID&)realNdrAsyncServerCall, detouredNdrAsyncServerCall) != NO_ERROR)
	{
		WRITE_DEBUG_MSG(TEXT("DetourAttach error on NdrServerCallAll"));
	}
	if (DetourAttach(&(PVOID&)realNdr64AsyncServerCallAll, detouredNdr64AsyncServerCallAll) != NO_ERROR)
	{
		WRITE_DEBUG_MSG(TEXT("DetourAttach error on Ndr64AsyncServerCallAll"));
	}
	if (DetourAttach(&(PVOID&)realNdr64AsyncServerCall64, detouredNdr64AsyncServerCall64) != NO_ERROR)
	{
		WRITE_DEBUG_MSG(TEXT("DetourAttach error on Ndr64AsyncServerCall64"));
	}
	if (DetourAttach(&(PVOID&)realNdrServerCallNdr64, detouredNdrServerCallNdr64) != NO_ERROR)
	{
		WRITE_DEBUG_MSG(TEXT("DetourAttach error on NdrServerCallNdr64"));
	}

	LONG errCode = DetourTransactionCommit();
	if (errCode != NO_ERROR)
	{
		wchar_t errMsg[MAX_PATH];
		_stprintf_s(errMsg, TEXT("RpcFirewall installation error, DetourTransactionCommit() failed :%d"), errCode);
		WRITE_DEBUG_MSG(errMsg);
		processProtectedEvent(false, myProcessName, myProcessID);
		unloadSelf();
		return;
	}
	else
	{
		WRITE_DEBUG_MSG(TEXT("RpcFirewall installed!"));
		processProtectedEvent(true, myProcessName, myProcessID);
	}

	waitForFurtherInstructions();
}

void dllDetached()
{
	WRITE_DEBUG_MSG(TEXT("RPCFirewall DLL Detached called..."));
	if (detouredFunctions)
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)realNdrStubCall2, detouredNdrStubCall2);
		DetourDetach(&(PVOID&)realNdrServerCallAll, detouredNdrServerCallAll);
		DetourDetach(&(PVOID&)realNdrAsyncServerCall, detouredNdrAsyncServerCall);
		DetourDetach(&(PVOID&)realNdr64AsyncServerCallAll, detouredNdr64AsyncServerCallAll);
		DetourDetach(&(PVOID&)realNdr64AsyncServerCall64, detouredNdr64AsyncServerCall64);
		DetourDetach(&(PVOID&)realNdrServerCallNdr64, detouredNdrServerCallNdr64);

		if (DetourTransactionCommit() == NO_ERROR)
		{
			WRITE_DEBUG_MSG(TEXT("RpcFirewall uninstalled."));
			processUnprotectedEvent(true, myProcessName, myProcessID);
		}
		else
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("RpcFirewall uninstall error: DetourTransactionCommit() failed!"));
			processUnprotectedEvent(false, myProcessName, myProcessID);
		}
	}

	if (uninstallEvent != NULL) CloseHandle(uninstallEvent);
	if (configurationUpdatedEvent != NULL) CloseHandle(configurationUpdatedEvent);
	if (managerDoneEvent != NULL) CloseHandle(managerDoneEvent);
	if (hConfigurationMapFile != NULL) CloseHandle(hConfigurationMapFile);

}

bool APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	GetModuleFileName(NULL, myProcessName, MAX_PATH);
	_stprintf_s(myProcessID, TEXT("%d"), GetCurrentProcessId());

    switch (ul_reason_for_call)
    {
		case DLL_PROCESS_ATTACH:
			myhModule = hModule;
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mainStart, NULL, 0,NULL);
			break;
		case DLL_PROCESS_DETACH:
			dllDetached();		
    }
    return true;
}

RpcEventParameters populateEventParameters(PRPC_MESSAGE pRpcMsg, wchar_t* szStringBindingServer, wchar_t* szStringBinding, wchar_t* functionName)
{
	RpcEventParameters eventParams = {};
	eventParams.functionName = std::wstring(functionName);
	eventParams.processID = std::wstring(myProcessID);
	eventParams.processName = std::wstring(myProcessName);


	std::wstring szWstringBindingServer = std::wstring(szStringBindingServer);
	std::wstring szWstringBinding = std::wstring(szStringBinding);

	size_t pos = szWstringBinding.find(_T(":"), 0);
	
	eventParams.protocol = szWstringBinding.substr(0, pos);
	eventParams.sourceAddress= szWstringBinding.substr(pos + 1, szWstringBinding.length() - pos);

	if (pos != std::string::npos) {
		szWstringBinding.replace(pos, 1, L",");
	}

	pos = szWstringBindingServer.find(_T("["));
	size_t endpos = szWstringBindingServer.find(_T("]"), pos + 1);
	eventParams.endpoint = szWstringBindingServer.substr(pos + 1, endpos - pos - 1);

	byte* byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

	_RPC_IF_ID* rpcifid = (_RPC_IF_ID*)(byteUuidPointer + 4);

	RPC_WSTR szStringUuid = NULL;
	RPC_STATUS status = UuidToString(&(rpcifid->Uuid), &szStringUuid);
	if (status == RPC_S_OK)
	{
		eventParams.uuidString = std::wstring((wchar_t*)szStringUuid);
		eventParams.OpNum = to_tstring<wchar_t>(pRpcMsg->ProcNum);

		RPC_AUTHZ_HANDLE Privs;
		unsigned long AuthnLevel;
		unsigned long AuthnSvc;
		unsigned long AuthzSvc;
		status = RpcBindingInqAuthClient(NULL, &Privs, NULL, &AuthnLevel, &AuthnSvc, &AuthzSvc);
		if (status == RPC_S_BINDING_HAS_NO_AUTH || status != RPC_S_OK)
		{
			eventParams.clientName = TEXT("UNKNOWN");
			eventParams.authnLevel = TEXT("UNKNOWN");
			eventParams.authnSvc = TEXT("UNKNOWN");
		}
		else
		{
			eventParams.clientName = (wchar_t*)Privs;
			eventParams.authnLevel = convertAuthLevelToString(AuthnLevel);
			eventParams.authnSvc = convertAuthSvcToString(AuthnSvc);
		}
	}

	if (szStringUuid != NULL) RpcStringFree(&szStringUuid);
	return eventParams;
}

void rpcFunctionVerboseOutput(bool allowCall, RpcEventParameters eventParams)
{
	std::wstring allowed(_T("Allowed"));
	if (!allowCall) allowed = _T("Blocked");
	if (verbose)
	{
		std::wstring verboseRpcCall(allowed + _T(",") + eventParams.functionName + _T(",") + eventParams.uuidString + _T(",") + eventParams.OpNum + _T(",") + eventParams.endpoint + _T(",") + eventParams.sourceAddress + _T(",") + eventParams.clientName + _T(",") + eventParams.authnLevel + _T(",") + eventParams.authnSvc);
		WRITE_DEBUG_MSG(verboseRpcCall.c_str());
	}
}

void RpcRuntimeCleanups(RPC_BINDING_HANDLE serverBinding,wchar_t* szStringBinding, wchar_t* szStringBindingServer)
{
	if (serverBinding != NULL) RpcBindingFree(&serverBinding);
	if (szStringBinding != NULL) RpcStringFree((RPC_WSTR*)&szStringBinding);
	if (szStringBindingServer != NULL) RpcStringFree((RPC_WSTR*)&szStringBindingServer);
}

bool processRPCCallInternal(wchar_t* functionName, PRPC_MESSAGE pRpcMsg)
{
	RPC_BINDING_HANDLE serverBinding = NULL;
	wchar_t* szStringBinding = NULL;
	wchar_t* szStringBindingServer = NULL;
	bool allowCall = true;
	bool auditCall = false;

	try {
		RPC_STATUS status;

		status = RpcBindingServerFromClient(0, &serverBinding);
		if (status != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_STATUS(_T("RpcBindingServerFromClient failed"), status);
			RpcRuntimeCleanups(serverBinding, szStringBinding, szStringBindingServer);

			return allowCall;
		}

		status = RpcBindingToStringBinding(serverBinding, (RPC_WSTR*)&szStringBinding);
		if (status != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_STATUS(_T("RpcBindingToStringBinding failed"), status);
			RpcRuntimeCleanups(serverBinding, szStringBinding, szStringBindingServer);

			return allowCall;
		}

		// Consider only calls over network transports
		if (_tcsstr(szStringBinding, _T("ncalrpc")) != NULL)
		{
			RpcRuntimeCleanups(serverBinding, szStringBinding, szStringBindingServer);

			return allowCall;
		}

		status = RpcBindingToStringBinding(pRpcMsg->Handle, (RPC_WSTR*)&szStringBindingServer);
		if (status != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_STATUS(_T("Could not extract server endpoint via RpcBindingToStringBinding"), status);
		}

		RpcEventParameters eventParams = populateEventParameters(pRpcMsg, szStringBindingServer, szStringBinding, functionName);
		auto configResult = checkIfRPCCallFiltered(eventParams);
		allowCall = !configResult.first;
		auditCall = configResult.second;
		rpcFunctionVerboseOutput(allowCall,eventParams);
		if (auditCall) rpcFunctionCalledEvent(allowCall, eventParams);
	}
	catch (const std::runtime_error& re) {
		WRITE_DEBUG_MSG_WITH_ERROR_MSG(TEXT("Exception: Runtime error during call"), (wchar_t*)re.what());
	}
	catch (const std::exception& ex) {
		WRITE_DEBUG_MSG_WITH_ERROR_MSG(TEXT("Exception: Runtime error during call"), (wchar_t*)ex.what());
	}
	catch (...) {
		WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Exception: Runtime error during call"));
	}

	RpcRuntimeCleanups(serverBinding, szStringBinding, szStringBindingServer);

	return allowCall;
}

void processRPCCall(wchar_t* functionName, PRPC_MESSAGE pRpcMsg)
{
	bool allowCall = processRPCCallInternal(functionName, pRpcMsg);
	if (!allowCall) {
		RpcRaiseException(ERROR_ACCESS_DENIED);
	}
}

long WINAPI detouredNdrStubCall2(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase)
{
	processRPCCall((wchar_t*)_T("NdrStubCall2"), pRpcMsg);

	return realNdrStubCall2(pThis, pChannel, pRpcMsg, pdwStubPhase);
}

void detouredNdrServerCallAll(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((wchar_t*)_T("NdrServerCallAll"), pRpcMsg);

	return realNdrServerCallAll(pRpcMsg);
}

void detouredNdrAsyncServerCall(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((wchar_t*)_T("NdrAsyncServerCall"), pRpcMsg);

	return realNdrAsyncServerCall(pRpcMsg);
}

void detouredNdr64AsyncServerCallAll(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((wchar_t*)_T("Ndr64AsyncServerCallAll"), pRpcMsg);

	return realNdr64AsyncServerCallAll(pRpcMsg);
}

void detouredNdr64AsyncServerCall64(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((wchar_t*)_T("Ndr64AsyncServerCall64"), pRpcMsg);

	return realNdr64AsyncServerCall64(pRpcMsg);
}

void detouredNdrServerCallNdr64(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((wchar_t*)_T("NdrServerCallNdr64"), pRpcMsg);

	return realNdrServerCallNdr64(pRpcMsg);
}
