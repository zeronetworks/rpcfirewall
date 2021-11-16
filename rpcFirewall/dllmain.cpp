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

HMODULE myhModule;

struct OpNumStruct
{
	BOOL anyOpnum;
	DWORD opnum;
};

struct UUIDStruct
{
	BOOL anyUUID;
	std::basic_string<TCHAR> uuid;
};

struct AddressStruct
{
	BOOL anyAddress;
	std::basic_string<TCHAR> address;
};

struct LineConfig
{
	UUIDStruct uuid;
	OpNumStruct opnum;
	AddressStruct source_addr;
	BOOL allow;
	BOOL audit;
	BOOL verbose;
};

std::basic_string<CHAR> privateConfigBuffer = {};

std::vector<LineConfig> configVectorOne = {};
std::vector<LineConfig> configVectorTwo = {};

enum ActiveConfigBufferNumber { One, Two};
ActiveConfigBufferNumber activeConfBufferNumber = One;
CHAR* mappedBuf = NULL;
BOOL AuditOnly = FALSE;
BOOL detouredFunctions = FALSE;
BOOL verbose = TRUE;
#define MUTEX_TIMEOUT_MS 15000
TCHAR myProcessName[MAX_PATH];
TCHAR myProcessID[16] = { 0 };

HANDLE uninstallEvent = NULL;
HANDLE configurationUpdatedEvent = NULL;
HANDLE managerDoneEvent = NULL;
HANDLE hConfigurationMapFile = NULL;

DWORD configurationVersion = 0;

template<typename T>
struct to_tstring_forwarder;

template<>
struct to_tstring_forwarder<char>
{
	template<typename U>
	static std::basic_string<char> to_tstring(U arg)
	{
		return std::to_string(arg);
	}
};

template<>
struct to_tstring_forwarder<wchar_t>
{
	template<typename U>
	static std::basic_string<wchar_t> to_tstring(U arg)
	{
		return std::to_wstring(arg);
	}
};

template<typename T, typename U>
std::basic_string<T> to_tstring(U arg)
{
	return to_tstring_forwarder<T>::to_tstring(arg);
}

void changeActiveConfigurationNumber()
{
	if (activeConfBufferNumber == One)
	{
		activeConfBufferNumber = Two;
	}
	else
	{
		activeConfBufferNumber = One;
	}
}

std::vector<LineConfig>& getActiveConfigurationVector()
{
	if (activeConfBufferNumber == One)
	{
		return configVectorOne;
	}
	return configVectorTwo;
}

std::vector<LineConfig>& getNonActiveConfigurationVector()
{
	if (activeConfBufferNumber == One)
	{
		return configVectorTwo;
	}
	return configVectorOne;
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

void writeDebugOutputWithPID(std::basic_string<TCHAR> dbgMsg)
{
	OutputDebugString(dbgMsg.c_str());
}

void writeDebugOutputWithPIDWithStatusMessage(std::basic_string<TCHAR> dbgMsg, DWORD status)
{
	std::basic_string<TCHAR> errMsg = dbgMsg + _T(" : ") + std::to_wstring(status);
	writeDebugOutputWithPID(errMsg);
}

void writeDebugOutputWithPIDWithErrorMessage(std::basic_string<TCHAR> dbgMsg, TCHAR* errMsgPtr)
{
	if (verbose)
	{
		TCHAR pidBuf[32];
		_stprintf_s(pidBuf, _T("%d"), GetCurrentProcessId());

		std::basic_string<TCHAR> finalMessage = pidBuf;
		std::basic_string<TCHAR> errMsg = errMsgPtr;

		finalMessage += TEXT(" - ");
		finalMessage += dbgMsg;
		finalMessage += TEXT(" : ");
		finalMessage += errMsg;

		writeDebugOutputWithPID(finalMessage.c_str());
	}
}

void writeDebugOutputWithPIDGetLastError(std::basic_string<TCHAR> dbgMsg)
{
	if (verbose)
	{

		TCHAR errBuf[32];
		_stprintf_s(errBuf, _T("%d"), GetLastError());

		std::basic_string<TCHAR> finalMessage = _T("");
		std::basic_string<TCHAR> errMsg = errBuf;

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

BOOL checkIfReleventRegisteredEndpointsForProcess()
{
	BOOL relevantEndpoint = FALSE;
	RPC_BINDING_VECTOR* binding_vector;
	RPC_WSTR szStringBinding;
	std::basic_string<TCHAR> allEndpoints = _T("Endpoint LIST:");
	std::basic_string<TCHAR> singleEndpoint;

	RPC_STATUS status = RpcServerInqBindings(&binding_vector);
	if (status == RPC_S_OK)
	{
		for (int i = 0; i < binding_vector->Count; i++)
		{
			status = RpcBindingToStringBinding(binding_vector->BindingH[i], &szStringBinding);
			if (status == RPC_S_OK)
			{
				singleEndpoint = (TCHAR*)szStringBinding;
				if (_tcsstr(singleEndpoint.c_str(), _T("ncalrpc")) == NULL)
				{
					relevantEndpoint = TRUE;
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
		relevantEndpoint = TRUE;
	}

	return relevantEndpoint;
}

BOOL checkIfRegisteredUUIDsForProcess()
{
	RPC_IF_ID_VECTOR* if_id_vector;
	RPC_WSTR szStringUuid;
	std::basic_string<TCHAR> allUUIDs = _T("UUID LIST:");
	std::basic_string<TCHAR> singleUUID;

	RPC_STATUS status = RpcMgmtInqIfIds(NULL, &if_id_vector);
	if (status == RPC_S_OK)
	{
		for (int i = 0; i < if_id_vector->Count; i++)
		{
			status = UuidToString(&(if_id_vector->IfId[i]->Uuid), &szStringUuid);
			if (status == RPC_S_OK)
			{
				singleUUID = (TCHAR*)szStringUuid;
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
		return FALSE;
	}

	return TRUE;
}

std::basic_string<TCHAR> convertAuthLevelToString(unsigned long authLvl)
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

std::basic_string<TCHAR> convertAuthSvcToString(unsigned long authSvc)
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

std::tuple<DWORD, DWORD, BOOL> getConfigOffsets(std::basic_string<CHAR> confStr)
{
	size_t start_pos = confStr.find("!start!");
	size_t end_pos = confStr.find("!end!");

	if (start_pos == std::string::npos || end_pos == std::string::npos)
	{
		WRITE_DEBUG_MSG(_T("Error reading start or end markers"));
		return std::make_tuple(0, 0, FALSE);
	}
	start_pos += 7;

	return std::make_tuple(start_pos, end_pos, TRUE);
}

std::wstring StringToWString(const std::string& s)
{
	std::wstring temp(s.length(), L' ');
	std::copy(s.begin(), s.end(), temp.begin());
	return temp;
}

std::basic_string<TCHAR> extractKeyValueFromConfigLine(std::basic_string<TCHAR> confLine, std::basic_string<TCHAR> key)
{
	confLine.replace(confLine.size() - 1, 1, _T(" "));
	size_t keyOffset = confLine.find(key);

	if (keyOffset == std::string::npos) return _T("\0");

	size_t nextKeyOffset = confLine.find(_T(" "), keyOffset + 1);

	if (nextKeyOffset == std::string::npos) return _T("\0");

	std::basic_string<TCHAR> val = confLine.substr(keyOffset + key.size(), nextKeyOffset - keyOffset - key.size());

	return val;
}

UUIDStruct extractUUIDFromConfigLine(std::basic_string<TCHAR> confLine)
{
	UUIDStruct uuidStr = {};
	uuidStr.uuid = extractKeyValueFromConfigLine(confLine, _T("uuid:"));
	
	if ((uuidStr.uuid).empty())
	{
		uuidStr.anyUUID = TRUE;
	}
	else
	{
		uuidStr.anyUUID = FALSE;
	}

	return uuidStr;
}

OpNumStruct extractOpNumFromConfigLine(std::basic_string<TCHAR> confLine)
{
	OpNumStruct opnumStruct = {};
	std::basic_string<TCHAR> opnumString = extractKeyValueFromConfigLine(confLine, _T("opnum:"));

	if (opnumString.empty())
	{
		opnumStruct.anyOpnum = TRUE;
	}
	else
	{
		try {
			opnumStruct.opnum = std::stoi(opnumString);
			opnumStruct.anyOpnum = FALSE;
		}
		catch (const std::invalid_argument& ia) {
			opnumStruct.anyOpnum = TRUE;
			WRITE_DEBUG_MSG(_T("Invalid opnum provided: ") + opnumString);
		}
	}
	return opnumStruct;
}

AddressStruct extractAddressFromConfigLine(std::basic_string<TCHAR> confLine)
{
	AddressStruct addrStruct = {};
	addrStruct.address = extractKeyValueFromConfigLine(confLine, _T("addr:"));

	if ((addrStruct.address).empty())
	{
		addrStruct.anyAddress = TRUE;
	}
	else
	{
		addrStruct.anyAddress = FALSE;
	}
	return addrStruct;
}

BOOL extractActionFromConfigLine(std::basic_string<TCHAR> confLine)
{
	std::basic_string<TCHAR> action = extractKeyValueFromConfigLine(confLine, _T("action:"));

	if (action.find(_T("block")) != std::string::npos)
	{
		return FALSE;
	}
	
	return TRUE;
}

BOOL extractAuditFromConfigLine(std::basic_string<TCHAR> confLine)
{
	std::basic_string<TCHAR> audit = extractKeyValueFromConfigLine(confLine, _T("audit:"));

	if (audit.find(_T("true")) != std::string::npos)
	{
		return TRUE;
	}

	return FALSE;
}

BOOL extractVerboseFromConfigLine(std::basic_string<TCHAR> confLine)
{
	std::basic_string<TCHAR> loc_verbose = extractKeyValueFromConfigLine(confLine, _T("verbose:"));
	if (loc_verbose.find(_T("true")) != std::string::npos)
	{
		return TRUE;
	}
	return FALSE;
}

void loadPrivateBufferToPassiveVectorConfiguration()
{
	WRITE_DEBUG_MSG(StringToWString(privateConfigBuffer));

	auto markers = getConfigOffsets(privateConfigBuffer);
	size_t start_pos = std::get<0>(markers);
	size_t end_pos = std::get<1>(markers);

	std::basic_string<CHAR> configurationOnly = privateConfigBuffer.substr(start_pos, end_pos - start_pos);

	std::basic_istringstream<TCHAR> configStream(StringToWString(configurationOnly));
	std::basic_string<TCHAR> confLineString;
	TCHAR configLine[256];

	size_t size = privateConfigBuffer.size() + 1;
	std::vector<LineConfig> passiveConfigVector = {};

	if (size > 1)
	{
		while (configStream.getline(configLine, 256))
		{
			confLineString = configLine;
			confLineString += _T(" ");
			LineConfig lineConfig = {};

			lineConfig.uuid = extractUUIDFromConfigLine(confLineString);
			lineConfig.opnum = extractOpNumFromConfigLine(confLineString);
			lineConfig.source_addr = extractAddressFromConfigLine(confLineString);
			lineConfig.allow = extractActionFromConfigLine(confLineString);
			lineConfig.audit = extractAuditFromConfigLine(confLineString);
			lineConfig.verbose = extractVerboseFromConfigLine(confLineString);
			passiveConfigVector.push_back(lineConfig);
		}
	}

	getNonActiveConfigurationVector() = passiveConfigVector;
}

BOOL checkKeyValueInConfigLine(TCHAR* confLine, TCHAR* key,DWORD keySize,std::basic_string<TCHAR> value)
{
	std::basic_string<TCHAR> confString = confLine;
	confString += _T("");

	size_t keyOffset = confString.find(key);
	if (keyOffset == std::string::npos) return TRUE;

	size_t keyEndOffset = confString.find(_T(" "), keyOffset);
	size_t configValueSize = keyEndOffset - keyOffset - keySize;
	
	if (configValueSize != value.size())
	{
		return FALSE;
	}

	auto configValueStr = confString.substr(keyOffset + keySize, configValueSize);

	return compareStringsCaseinsensitive((TCHAR*)configValueStr.c_str(), (TCHAR*)value.c_str(), configValueSize);
}

BOOL checkAudit(TCHAR* confLine)
{
	if (_tcsstr(confLine, TEXT("audit:true")))
	{
		return TRUE;
	}
	return FALSE;
}

BOOL checkUUID(UUIDStruct uuidStructure, std::basic_string<TCHAR> uuidString)
{
	if (uuidStructure.anyUUID)
	{
		return TRUE;
	}
	return uuidStructure.uuid.find(uuidString) != std::string::npos;
}

BOOL checkOpNum(OpNumStruct opnumStructure, std::basic_string<TCHAR> opNum)
{
	if (opnumStructure.anyOpnum)
	{
		return TRUE;
	}
	return (opnumStructure.opnum == std::stoi(opNum));
}

BOOL checkAddress(AddressStruct addrStructure, std::basic_string<TCHAR> srcAddr)
{
	if (addrStructure.anyAddress)
	{
		return TRUE;
	}
	return (addrStructure.address == srcAddr);
}

std::pair<BOOL,BOOL> checkIfRPCCallFiltered(RpcEventParameters rpcEvent)
{
	std::vector<LineConfig> configurationVector = getActiveConfigurationVector();

	BOOL UUIDMatch, AddressMatch, OpNumMatch, auditCall, filterCall = FALSE;
	DWORD verboseCount = 0;
	for (LineConfig lc : configurationVector)
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
	std::string mappedBufStr = mappedBuf;
	privateConfigBuffer = mappedBufStr;
}

BOOL isNewVersion()
{
	size_t verLoc = privateConfigBuffer.find("ver:");
	if (verLoc == std::string::npos)
	{
		WRITE_DEBUG_MSG(_T("No version keyword found"));
		return FALSE;
	}
	size_t verEndPos = privateConfigBuffer.find(" ") + 1;
	DWORD newVersion = std::stoi(privateConfigBuffer.substr(verLoc + 4, verEndPos - 5));
	
	if (newVersion > configurationVersion)
	{
		WRITE_DEBUG_MSG(_T("New configuration version detected."));
		configurationVersion = newVersion;
		return TRUE;
	}

	return FALSE;
}

BOOL isHashValid()
{
	BOOL validConfig = FALSE;
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

	size_t calculatedHashValue = std::hash<std::basic_string<CHAR>>{}(privateConfigBuffer.substr(start_pos,end_pos - start_pos));

	if (calculatedHashValue == declaredHashVal)
	{
		validConfig = TRUE;
	}

	return validConfig;
}

BOOL checkIfVerbose()
{
	std::vector<LineConfig> configurationVector = getActiveConfigurationVector();

	for (LineConfig lc : configurationVector)
	{
		if (lc.verbose)
		{
			return TRUE;
		}
	}
	return FALSE;
}

void loadConfigurationFromMappedMemory()
{
	if (hConfigurationMapFile == NULL)
	{
		WRITE_DEBUG_MSG(_TEXT("Calling OpenFileMapping..."));
		hConfigurationMapFile = OpenFileMapping(FILE_MAP_READ, FALSE, GLOBAL_SHARED_MEMORY);

		if (hConfigurationMapFile == NULL)
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Could not open configuration. Auditing only..."));
			AuditOnly = TRUE;

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
				changeActiveConfigurationNumber();
				verbose = checkIfVerbose();
			}
			break;
		}
	}
}

void writeEventToDebugOutput(RpcEventParameters eventParams, BOOL allowCall)
{
	std::basic_string<TCHAR> dbgMsg = _T("");
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
	HANDLE uninstallEvent = OpenEvent(SYNCHRONIZE, FALSE, GLOBAL_RPCFW_EVENT_UNPROTECT);

	if (uninstallEvent != NULL)
	{
		HANDLE allEvents[2];
		allEvents[0] = uninstallEvent;
		allEvents[1] = configurationUpdatedEvent;
		BOOL keepOnSpinning = true;

		while (keepOnSpinning)
		{
			DWORD dwWaitResult = WaitForSingleObject(uninstallEvent, 10000);
			//DWORD dwWaitResult = WaitForMultipleObjects(2, allEvents, FALSE, INFINITE);
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

	detouredFunctions = TRUE;

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
		TCHAR errMsg[MAX_PATH];
		_stprintf_s(errMsg, TEXT("RpcFirewall installation error, DetourTransactionCommit() failed :%d"), errCode);
		WRITE_DEBUG_MSG(errMsg);
		processProtectedEvent(FALSE, myProcessName, myProcessID);
		unloadSelf();
		return;
	}
	else
	{
		WRITE_DEBUG_MSG(TEXT("RpcFirewall installed!"));
		processProtectedEvent(TRUE, myProcessName, myProcessID);
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
			processUnprotectedEvent(TRUE, myProcessName, myProcessID);
		}
		else
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("RpcFirewall uninstall error: DetourTransactionCommit() failed!"));
			processUnprotectedEvent(FALSE, myProcessName, myProcessID);
		}
	}

	if (uninstallEvent != NULL) CloseHandle(uninstallEvent);
	if (configurationUpdatedEvent != NULL) CloseHandle(configurationUpdatedEvent);
	if (managerDoneEvent != NULL) CloseHandle(managerDoneEvent);
	if (hConfigurationMapFile != NULL) CloseHandle(hConfigurationMapFile);

}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
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
    return TRUE;
}

RpcEventParameters populateEventParameters(PRPC_MESSAGE pRpcMsg, TCHAR* szStringBindingServer, TCHAR* szStringBinding, TCHAR* functionName)
{
	RpcEventParameters eventParams = {};
	eventParams.functionName = std::basic_string<TCHAR>(functionName);
	eventParams.processID = std::basic_string<TCHAR>(myProcessID);
	eventParams.processName = std::basic_string<TCHAR>(myProcessName);


	std::basic_string<TCHAR> szWstringBindingServer = std::basic_string<TCHAR>(szStringBindingServer);
	std::basic_string<TCHAR> szWstringBinding = std::basic_string<TCHAR>(szStringBinding);

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
		eventParams.uuidString = std::basic_string<TCHAR>((TCHAR*)szStringUuid);
		eventParams.OpNum = to_tstring<TCHAR>(pRpcMsg->ProcNum);

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
			eventParams.clientName = (TCHAR*)Privs;
			eventParams.authnLevel = convertAuthLevelToString(AuthnLevel);
			eventParams.authnSvc = convertAuthSvcToString(AuthnSvc);
		}
	}

	if (szStringUuid != NULL) RpcStringFree(&szStringUuid);
	return eventParams;
}

void rpcFunctionVerboseOutput(BOOL allowCall, RpcEventParameters eventParams)
{
	std::basic_string<TCHAR> allowed(_T("Allowed"));
	if (!allowCall) allowed = _T("Blocked");
	if (verbose)
	{
		std::basic_string<TCHAR> verboseRpcCall(allowed + _T(",") + eventParams.functionName + _T(",") + eventParams.uuidString + _T(",") + eventParams.OpNum + _T(",") + eventParams.endpoint + _T(",") + eventParams.sourceAddress + _T(",") + eventParams.clientName + _T(",") + eventParams.authnLevel + _T(",") + eventParams.authnSvc);
		WRITE_DEBUG_MSG(verboseRpcCall.c_str());
	}
}

void RpcRuntimeCleanups(RPC_BINDING_HANDLE serverBinding,TCHAR* szStringBinding, TCHAR* szStringBindingServer)
{
	if (serverBinding != NULL) RpcBindingFree(&serverBinding);
	if (szStringBinding != NULL) RpcStringFree((RPC_WSTR*)&szStringBinding);
	if (szStringBindingServer != NULL) RpcStringFree((RPC_WSTR*)&szStringBindingServer);
}

BOOL processRPCCallInternal(TCHAR* functionName, PRPC_MESSAGE pRpcMsg)
{
	RPC_BINDING_HANDLE serverBinding = NULL;
	TCHAR* szStringBinding = NULL;
	TCHAR* szStringBindingServer = NULL;
	BOOL allowCall = TRUE;
	BOOL auditCall = FALSE;

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
		WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Exception: Runtime error during call"), (TCHAR*)re.what());
	}
	catch (const std::exception& ex) {
		WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Exception: Runtime error during call"), (TCHAR*)ex.what());
	}
	catch (...) {
		WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Exception: Runtime error during call"));
	}

	RpcRuntimeCleanups(serverBinding, szStringBinding, szStringBindingServer);

	return allowCall;
}

void processRPCCall(TCHAR* functionName, PRPC_MESSAGE pRpcMsg)
{
	BOOL allowCall = processRPCCallInternal(functionName, pRpcMsg);
	if (!allowCall) {
		RpcRaiseException(ERROR_ACCESS_DENIED);
	}
}

long WINAPI detouredNdrStubCall2(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase)
{
	processRPCCall((TCHAR*)_T("NdrStubCall2"), pRpcMsg);

	return realNdrStubCall2(pThis, pChannel, pRpcMsg, pdwStubPhase);
}

void detouredNdrServerCallAll(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((TCHAR*)_T("NdrServerCallAll"), pRpcMsg);

	return realNdrServerCallAll(pRpcMsg);
}

void detouredNdrAsyncServerCall(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((TCHAR*)_T("NdrAsyncServerCall"), pRpcMsg);

	return realNdrAsyncServerCall(pRpcMsg);
}

void detouredNdr64AsyncServerCallAll(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((TCHAR*)_T("Ndr64AsyncServerCallAll"), pRpcMsg);

	return realNdr64AsyncServerCallAll(pRpcMsg);
}

void detouredNdr64AsyncServerCall64(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((TCHAR*)_T("Ndr64AsyncServerCall64"), pRpcMsg);

	return realNdr64AsyncServerCall64(pRpcMsg);
}

void detouredNdrServerCallNdr64(PRPC_MESSAGE pRpcMsg)
{
	processRPCCall((TCHAR*)_T("NdrServerCallNdr64"), pRpcMsg);

	return realNdrServerCallNdr64(pRpcMsg);
}
