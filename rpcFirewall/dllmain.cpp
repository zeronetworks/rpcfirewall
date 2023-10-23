// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <ws2tcpip.h>
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
#include <iomanip>
#include "config.hpp"
#include "rpcWrappers.hpp"
#include <sddl.h>

#pragma comment(lib, "Ws2_32.lib")

HMODULE myhModule;

DoubleBufferedConfig config;
std::string privateConfigBuffer = {};

CHAR* mappedBuf = nullptr;
bool AuditOnly = false;
bool detouredFunctions = false;
bool verbose = true;
#define MUTEX_TIMEOUT_MS 15000
wchar_t myProcessName[MAX_PATH];
wchar_t myProcessID[16] = { 0 };

HANDLE uninstallEvent = nullptr;
HANDLE configurationUpdatedEvent = nullptr;
HANDLE managerDoneEvent = nullptr;
HANDLE hConfigurationMapFile = nullptr;

DWORD configurationVersion = 0;

template<typename T, typename U>
std::basic_string<T> to_tstring(U arg)
{
	constexpr bool statAssert = true;
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
		statAssert = false;
		static_assert(statAssert);
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

bool checkFWConfig(const wchar_t* confLine)
{
	return _tcsstr(confLine, TEXT("fw:"));
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
				if (_tcsstr(singleEndpoint.c_str(), _T("ncalrpc")) == nullptr)
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

	RPC_STATUS status = RpcMgmtInqIfIds(nullptr, &if_id_vector);
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

void createMinIPv6(std::array<UINT16, 8>& ipv6, int maskLength) {

	int fullBlocks = maskLength / 16;
	int remainingBits = maskLength % 16;

	for (int i = fullBlocks + 1; i < 8; ++i) {
		ipv6[i] = 0;
	}

	int mask = (1 << (16 - remainingBits)) - 1;
	ipv6[fullBlocks] &= ~mask;
}

void createMaxIPv6(std::array<UINT16, 8>& ipv6, int maskLength) {

	int fullBlocks = maskLength / 16;
	int remainingBits = maskLength % 16;

	for (int i = fullBlocks + 1; i < 8; ++i) {
		ipv6[i] = 0xFFFF;
	}

	int mask = (1 << (16 - remainingBits)) - 1;
	ipv6[fullBlocks] |= mask;

}

bool IsAddress1SmallerThanAddress2(std::array<UINT16, 8>& addr1, std::array<UINT16, 8>& addr2)
{
	for (int i = 0; i < 8; i++)
	{
		if (addr1[i] < addr2[i])
		{	
			return true;
		}
	}
	return false;
}

bool IsAddress1BiggerThanAddress2(std::array<UINT16, 8>& addr1, std::array<UINT16, 8>& addr2)
{
	for (int i = 0; i < 8; i++)
	{
		if (addr1[i] > addr2[i])
		{
			return true;
		}
	}
	return false;
}

bool IsAddress1BiggerThanAddress2(const std::wstring &addr1, std::array<UINT16, 8>& addr2)
{
	UINT8 ipv6arr[16];
	std::array<UINT16, 8> ipv6Arr16 = {0};

	if (InetPton(AF_INET6, addr1.c_str(), ipv6arr) == 1)
	{
		for (int i = 0; i < 8; i++)
		{
			ipv6Arr16[i] = ipv6arr[2 * i] * 256 + ipv6arr[2 * i + 1];
		}

	}

	return IsAddress1BiggerThanAddress2(ipv6Arr16, addr2);
}

bool IsAddress1SmallerThanAddress2(const std::wstring& addr1, std::array<UINT16, 8>& addr2)
{
	UINT8 ipv6arr[16];
	std::array<UINT16, 8> ipv6Arr16 = { 0 };

	if (InetPton(AF_INET6, addr1.c_str(), ipv6arr) == 1)
	{
		for (int i = 0; i < 8; i++)
		{
			ipv6Arr16[i] = ipv6arr[2 * i] * 256 + ipv6arr[2 * i + 1];
		}
	}

	return IsAddress1SmallerThanAddress2(ipv6Arr16, addr2);
}

bool isIpv4Addr(const std::wstring& testIp)
{
	UINT32 ipv4;

	if (InetPton(AF_INET, testIp.c_str(), &ipv4) <= 0) return false;

	return true;
}

bool isIPv4CIDR(const std::wstring& testIp)
{
	UINT32 ipv4;

	size_t slashPos = testIp.find(L"/");
	if (slashPos == std::string::npos) {
		return false;
	}

	unsigned int prefixLength;

	try {
		prefixLength = std::stoi(testIp.substr(slashPos + 1));
	}
	catch (const std::exception&) {
		return false;
	}

	std::wstring ipOnly = testIp.substr(0, slashPos);
	if (!isIpv4Addr(ipOnly) || prefixLength > 32)
	{
		return false;
	}

	return true;
}

bool isIpv6Address(const std::wstring& testIp)
{
	BYTE ipv6[16];

	if (InetPton(AF_INET6, testIp.c_str(), &ipv6) <= 0) return false;

	return true;

}

bool isIPv6CIDR(const std::wstring& testIp)
{
	UINT8 ipv6[16];

	size_t slashPos = testIp.find(L"/");
	if (slashPos == std::string::npos) {
		return false;
	}

	unsigned int prefixLength;

	try {
		prefixLength = std::stoi(testIp.substr(slashPos + 1));
	}
	catch (const std::exception&) {
		return false;
	}

	std::wstring ipOnly = testIp.substr(0, slashPos);
	if (!isIpv6Address(ipOnly) || prefixLength > 128)
	{
		return false;
	}

	return true;
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
	std::wstring uuid = extractKeyValueFromConfigLine(confLine, _T("uuid:"));
	
	std::transform(uuid.begin(), uuid.end(), uuid.begin(), ::tolower);

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

unsigned long Ipv4StringToNumber(const std::wstring &ipv4)
{
	unsigned long ipv4Number;
	InetPton(AF_INET, ipv4.c_str(), &ipv4Number);
	return ntohl(ipv4Number);
}

AddressRangeIpv4 getMinMaxAddressesIPv4(const std::wstring& ipAddressCIDR) {
	
	size_t slashPos = ipAddressCIDR.find(L"/");
	if (slashPos == std::string::npos) {
		return AddressRangeIpv4{};
	}

	unsigned int prefixLength;

	try {
		prefixLength = std::stoi(ipAddressCIDR.substr(slashPos + 1));
	}
	catch (const std::exception&) {
		return AddressRangeIpv4{};
	}

	std::wstring ipOnly = ipAddressCIDR.substr(0, slashPos);
	if (!isIpv4Addr(ipOnly) || prefixLength > 32)
	{
		return AddressRangeIpv4{};
	}

	 unsigned long baseAddress = Ipv4StringToNumber(ipOnly);

	// Calculate the minimum and maximum addresses
	unsigned long mask = static_cast<unsigned long>(std::pow(2, 32 - prefixLength)) - 1;
	unsigned long minAddress = baseAddress & ~mask;
	unsigned long maxAddress = baseAddress | mask;

	AddressRangeIpv4 aripv4;
	aripv4.minAddr = minAddress;
	aripv4.maxAddr = maxAddress;
	return aripv4;

}

AddressRangeIpv6 getMinMaxAddressesIpv6(const std::wstring& ipAddress) {
	UINT8 ipv6arr[16];
	AddressRangeIpv6 aripv6 = {};


	size_t slashPos = ipAddress.find(L"/");
	if (slashPos == std::string::npos) {
		//regular address
		if (InetPton(AF_INET6, ipAddress.c_str(), ipv6arr) == 1) 
		{
			for (int i = 0; i < 8; i++)
			{
				aripv6.minAddr[i] = aripv6.maxAddr[i] = ipv6arr[2 * i] * 256 + ipv6arr[2 * i + 1];
			}

		}
	}
	else
	{
		unsigned int prefixLength;

		try {
			prefixLength = std::stoi(ipAddress.substr(slashPos + 1));
		}
		catch (const std::exception&) {
			return AddressRangeIpv6{};
		}

		std::wstring ipOnly = ipAddress.substr(0, slashPos);
		if (isIpv6Address(ipOnly) && prefixLength < 129)
		{

			if (InetPton(AF_INET6, ipOnly.c_str(), ipv6arr) == 1) {

				for (int i = 0; i < 8; i++)
				{
					aripv6.minAddr[i] = aripv6.maxAddr[i] = ipv6arr[2 * i] * 256 + ipv6arr[2 * i + 1];
				}

				createMinIPv6(aripv6.minAddr, prefixLength);
				createMaxIPv6(aripv6.maxAddr, prefixLength);
			}
		}
	}

	return aripv6;
}

AddressRangeFilter extractAddressFromConfigLine(const std::wstring& confLine)
{
	WRITE_DEBUG_MSG(L"Extracting address from config");
	const std::wstring address = extractKeyValueFromConfigLine(confLine, _T("addr:"));
	AddressRange addrRange = AddressRange{};

	if (!address.empty())
	{
		if (isIPv4CIDR(address))
		{
			addrRange.ipv4 = getMinMaxAddressesIPv4(address);
			addrRange.ipv6 = AddressRangeIpv6{};
			WRITE_DEBUG_MSG_WITH_STATUS(L"Got IPv4 CIDR address with min value: ",addrRange.ipv4->minAddr);
		}
		else if (isIPv6CIDR(address))
		{
			addrRange.ipv4 = AddressRangeIpv4{};
			addrRange.ipv6 = getMinMaxAddressesIpv6(address);
			WRITE_DEBUG_MSG(L"Got IPv6 CIDR address");
		}
		else if (isIpv4Addr(address))
		{
			unsigned long addrNum = Ipv4StringToNumber(address);
			AddressRangeIpv4 aripv4;
			aripv4.minAddr = addrNum;
			aripv4.maxAddr = addrNum;
			
			addrRange.ipv4 = aripv4;
			WRITE_DEBUG_MSG_WITH_STATUS(L"Got regular IPv4 address with min value: ", addrRange.ipv4->minAddr);
			addrRange.ipv6 = AddressRangeIpv6{};
		}
		else if (isIpv6Address(address))
		{
			WRITE_DEBUG_MSG(L"Got IPv6 regular address");
			addrRange.ipv4 = AddressRangeIpv4{};
			addrRange.ipv6 = getMinMaxAddressesIpv6(address);
		}
	}
	return AddressRangeFilter{ addrRange };
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

bool extractVerboseFromConfigLine(const std::wstring& confLine)
{
	std::wstring loc_verbose = extractKeyValueFromConfigLine(confLine, _T("verbose:"));

	return loc_verbose.find(_T("true")) != std::string::npos;
}

protocolFilter extractProtocolFromConfigLine(const std::wstring& confLine)
{
	std::wstring protocol = extractKeyValueFromConfigLine(confLine, _T("prot:"));

	std::transform(protocol.begin(), protocol.end(), protocol.begin(), ::tolower);

	return protocol.empty() ? protocolFilter{} : protocolFilter{ protocol };
}

SIDFilter extraceSIDFromConfigLine(const std::wstring& confLine)
{
	std::wstring sid = extractKeyValueFromConfigLine(confLine, _T("sid:"));

	std::transform(sid.begin(), sid.end(), sid.begin(), ::toupper);

	return sid.empty() ? SIDFilter{} : SIDFilter{ sid };

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

			if (checkFWConfig(confLineString.c_str()))
			{
				LineConfig lineConfig = {};

				lineConfig.uuid = extractUUIDFilterFromConfigLine(confLineString);
				lineConfig.opnum = extractOpNumFilterFromConfigLine(confLineString);
				lineConfig.addr = extractAddressFromConfigLine(confLineString);
				lineConfig.policy = extractPolicyFromConfigLine(confLineString);
				lineConfig.verbose = extractVerboseFromConfigLine(confLineString);
				lineConfig.protocol = extractProtocolFromConfigLine(confLineString);
				lineConfig.sid = extraceSIDFromConfigLine(confLineString);

				passiveConfigVector.push_back(lineConfig);
			}
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

bool checkAddress(const AddressRangeFilter& addrRangeFilter, const std::wstring& srcAddr)
{
	WRITE_DEBUG_MSG(L"Checking address filter...");
	if (!addrRangeFilter.has_value())
	{
		WRITE_DEBUG_MSG(L"address range has no value. Match.");
		return true;
	}
	
	if (isIpv4Addr(srcAddr))
	{
		if (!(addrRangeFilter.value().ipv4.has_value()))
		{
			WRITE_DEBUG_MSG(L"Ipv4 Match because no ipv4 address to compare to...");
			return true;
		}

		UINT32 srcAddrNum = Ipv4StringToNumber(srcAddr);
		std::wstring msg = L"Checking if " + std::to_wstring(srcAddrNum) + L" is between " + std::to_wstring(addrRangeFilter.value().ipv4.value().minAddr) + L" and " + std::to_wstring(addrRangeFilter.value().ipv4.value().maxAddr);
		WRITE_DEBUG_MSG (msg.c_str());
		return (srcAddrNum >= addrRangeFilter.value().ipv4.value().minAddr) && (srcAddrNum <= addrRangeFilter.value().ipv4.value().maxAddr);
		
	}

	if (isIpv6Address(srcAddr))
	{
		if (!(addrRangeFilter.value().ipv6.has_value()))
		{
			WRITE_DEBUG_MSG(L"IPv6 has no value. Match.");
			return true;
		}
		AddressRangeIpv6 addrRangeIpv6 = addrRangeFilter.value().ipv6.value();

		WRITE_DEBUG_MSG(L"Checking if IPv6 is in range...");
		WRITE_DEBUG_MSG(std::wstring(L"received address: ") + srcAddr);

		return !(IsAddress1BiggerThanAddress2(srcAddr, addrRangeIpv6.maxAddr) || IsAddress1SmallerThanAddress2(srcAddr, addrRangeIpv6.minAddr));
	}

	return true;
}

bool checkProtocol(const protocolFilter& protFilter, const std::wstring& protocol)
{
	if (!protFilter.has_value())
	{
		return true;
	}

	std::wstring protFilterString = protFilter.value();
	std::wstring protocolString = protocol;

	std::transform(protocolString.begin(), protocolString.end(), protocolString.begin(), ::tolower);
	std::transform(protFilterString.begin(), protFilterString.end(), protFilterString.begin(), ::tolower);

	if (protocolString.find(protFilterString) != std::string::npos)
	{
		return true;
	}
	
	return false;
}

// Function to check if the RPC caller has access based on the security descriptor
bool checkIfSIDBelongstoSD(SIDFilter sidFilter)
{
	WRITE_DEBUG_MSG(_T("Entering checkIfSIDBelongstoSD ..."));
	if (!sidFilter.has_value())
	{
		return true;
	}

	std::wstring securityDescriptorString = L"O:BAG:BAD:(A;;FA;;;" + sidFilter.value() + L")";

	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
	
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(securityDescriptorString.c_str(),
		SDDL_REVISION_1, &pSecurityDescriptor, nullptr))
	{
		WRITE_DEBUG_MSG(_T("ConvertStringSecurityDescriptorToSecurityDescriptorW failed..."));
		return false;
	}

	WRITE_DEBUG_MSG(_T("Calling RpcImpersonateClient"));

	RPC_STATUS status = RpcImpersonateClient(nullptr);
	if (status != RPC_S_OK)
	{
		WRITE_DEBUG_MSG_WITH_STATUS(_T("RpcImpersonateClient failed"), status);
		LocalFree(pSecurityDescriptor);
		return false;
	}

	HANDLE hToken = nullptr;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, true, &hToken))
	{
		WRITE_DEBUG_MSG_WITH_GETLASTERROR(_T("OpenThreadToken failed"));
		RpcRevertToSelf();
		LocalFree(pSecurityDescriptor);
		return false;
	}

	GENERIC_MAPPING mapping;
	mapping.GenericRead = FILE_GENERIC_READ;
	mapping.GenericExecute = FILE_GENERIC_EXECUTE;
	mapping.GenericWrite = FILE_GENERIC_WRITE;
	mapping.GenericAll = FILE_ALL_ACCESS;

	DWORD dwAccessDesired = FILE_GENERIC_READ;
	MapGenericMask(&dwAccessDesired, &mapping);

	DWORD dwAccessGranted;
	BOOL bResult;
	BOOL bAccessStatus = FALSE;
	PRIVILEGE_SET PrivilegeSet;
	DWORD dwPrivSetSize = sizeof(PRIVILEGE_SET);

	PrivilegeSet.PrivilegeCount = 0;
	PrivilegeSet.Control = 0;
	bResult = AccessCheck(pSecurityDescriptor, hToken, dwAccessDesired, &mapping, &PrivilegeSet, &dwPrivSetSize, &dwAccessGranted, &bAccessStatus);
	if (!bResult)
	{
		WRITE_DEBUG_MSG_WITH_GETLASTERROR(_T("AccessCheck failed"));
	}

	WRITE_DEBUG_MSG_WITH_STATUS(_T("AccessCheck returned "), bAccessStatus);

	RpcRevertToSelf();
	LocalFree(pSecurityDescriptor);
	CloseHandle(hToken);
	return bAccessStatus;
}

RpcCallPolicy getMatchingPolicy(const RpcEventParameters& rpcEvent)
{
	const ConfigVector& configurationVector = config.getActiveConfigurationVector();

	for (const LineConfig& lc : configurationVector)
	{
		const bool UUIDMatch = checkUUID(lc.uuid, rpcEvent.uuidString);
		const bool AddressMatch = checkAddress(lc.addr, rpcEvent.sourceAddress);
		const bool OpNumMatch = checkOpNum(lc.opnum, rpcEvent.OpNum);
		const bool ProtocolMatch = checkProtocol(lc.protocol, rpcEvent.protocol);	
		const bool SIDMatch = checkIfSIDBelongstoSD(lc.sid);

		if (UUIDMatch && AddressMatch && OpNumMatch && ProtocolMatch && SIDMatch)
		{
			WRITE_DEBUG_MSG(_T("Rule Matched for RPC call."));

			return lc.policy;
		}
	}

	return RpcCallPolicy{};
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
	if (hConfigurationMapFile == nullptr)
	{
		WRITE_DEBUG_MSG(_TEXT("Calling OpenFileMapping..."));
		hConfigurationMapFile = OpenFileMapping(FILE_MAP_READ, false, GLOBAL_SHARED_MEMORY);

		if (hConfigurationMapFile == nullptr)
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Could not open configuration. Auditing only..."));
			AuditOnly = true;

			return;
		}
	}
	
	if (mappedBuf == nullptr)
	{
		WRITE_DEBUG_MSG(_TEXT("Calling MapViewOfFile..."));
		mappedBuf = (CHAR*)MapViewOfFile(hConfigurationMapFile, FILE_MAP_READ, 0, 0, MEM_BUF_SIZE);

		if (mappedBuf == nullptr)
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(TEXT("Error: Could not map view of file."));
			CloseHandle(hConfigurationMapFile);
			hConfigurationMapFile = nullptr;

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

	if (uninstallEvent != nullptr)
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
}

struct AutoUnloader
{
	~AutoUnloader()
	{
		FreeLibraryAndExitThread(myhModule, 0);
	}
};

void mainStart()
{
	AutoUnloader autoUnloader;

	WRITE_DEBUG_MSG(TEXT("RPCFirewall DLL Loaded..."));
	if (!checkIfRegisteredUUIDsForProcess())
	{
		return;
	}

	if (!checkIfReleventRegisteredEndpointsForProcess() && _tcsstr(myProcessName,_T("spoolsv.exe")) == nullptr)
	{
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
		return;
	}

	WRITE_DEBUG_MSG(TEXT("RpcFirewall installed!"));
	processProtectedEvent(true, myProcessName, myProcessID);

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

	if (uninstallEvent != nullptr) CloseHandle(uninstallEvent);
	if (configurationUpdatedEvent != nullptr) CloseHandle(configurationUpdatedEvent);
	if (managerDoneEvent != nullptr) CloseHandle(managerDoneEvent);
	if (hConfigurationMapFile != nullptr) CloseHandle(hConfigurationMapFile);

}

bool APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	GetModuleFileName(nullptr, myProcessName, MAX_PATH);
	_stprintf_s(myProcessID, TEXT("%d"), GetCurrentProcessId());

    switch (ul_reason_for_call)
    {
		case DLL_PROCESS_ATTACH:
			myhModule = hModule;
			CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mainStart, nullptr, 0,nullptr);
			break;
		case DLL_PROCESS_DETACH:
			dllDetached();		
    }
    return true;
}

std::wstring GetClientSIDString()
{
	std::wstring clientSID = L"S-1-0-0";

	RPC_STATUS status = RpcImpersonateClient(nullptr);
	if (status != RPC_S_OK)
	{
		WRITE_DEBUG_MSG_WITH_STATUS(_T("RpcImpersonateClient failed during GetClientSIDString"), status);
		return clientSID;
	}

	HANDLE hToken = nullptr;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, true, &hToken))
	{
		WRITE_DEBUG_MSG_WITH_GETLASTERROR(_T("OpenThreadToken failed during GetClientSIDString"));
	}
	else
	{
		DWORD dwSize = 0;
		if (!GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			WRITE_DEBUG_MSG_WITH_GETLASTERROR(_T("failed to get token information size"));
		}
		else
		{
			PTOKEN_USER tokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
			if (tokenUser == nullptr)
			{
				WRITE_DEBUG_MSG_WITH_GETLASTERROR(_T("failed to allocate token information buffer"));
			}
			else
			{
				if (!GetTokenInformation(hToken, TokenUser, tokenUser, dwSize, &dwSize))
				{
					WRITE_DEBUG_MSG_WITH_GETLASTERROR(_T("failed to get token information"));
				}
				else
				{
					LPWSTR sidString = nullptr;
					if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString))
					{
						WRITE_DEBUG_MSG_WITH_GETLASTERROR(_T("failed to convert sid to string"));
					}
					clientSID.assign(sidString);
				}

				LocalFree(tokenUser);
			}
		}

		CloseHandle(hToken);
	}

	RevertToSelf();
	
	return clientSID;
}

RpcEventParameters populateEventParameters(PRPC_MESSAGE pRpcMsg, wchar_t* szStringBindingServer, wchar_t* szStringBinding, wchar_t* functionName, std::wstring &srcAddr, unsigned short srcPort, std::wstring& dstAddr, unsigned short dstPort)
{
	RpcEventParameters eventParams = {};
	eventParams.functionName = std::wstring(functionName);
	eventParams.processID = std::wstring(myProcessID);
	eventParams.processName = std::wstring(myProcessName);
	eventParams.clientSID = GetClientSIDString();
	
	std::wstring srcPrt = std::to_wstring(srcPort);
	eventParams.srcPort  = srcPrt;
	std::wstring dstPrt = std::to_wstring(dstPort);
	eventParams.dstPort = dstPrt;

	std::wstring szWstringBindingServer = std::wstring(szStringBindingServer);
	std::wstring szWstringBinding = std::wstring(szStringBinding);

	size_t pos = szWstringBinding.find(_T(":"), 0);
	
	eventParams.protocol = szWstringBinding.substr(0, pos);
	srcAddr.empty() ? eventParams.sourceAddress = szWstringBinding.substr(pos + 1, szWstringBinding.length() - pos) : eventParams.sourceAddress = srcAddr;
	dstAddr.empty() ? eventParams.destAddress = _T("0.0.0.0") : eventParams.destAddress = dstAddr;

	if (pos != std::string::npos) {
		szWstringBinding.replace(pos, 1, L",");
	}

	pos = szWstringBindingServer.find(_T("["));
	size_t endpos = szWstringBindingServer.find(_T("]"), pos + 1);
	eventParams.endpoint = szWstringBindingServer.substr(pos + 1, endpos - pos - 1);

	byte* byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

	_RPC_IF_ID* rpcifid = (_RPC_IF_ID*)(byteUuidPointer + 4);

	RPC_WSTR szStringUuid = nullptr;
	RPC_STATUS status = UuidToString(&(rpcifid->Uuid), &szStringUuid);
	if (status == RPC_S_OK)
	{
		eventParams.uuidString = std::wstring((wchar_t*)szStringUuid);
		eventParams.OpNum = to_tstring<wchar_t>(pRpcMsg->ProcNum);

		RPC_AUTHZ_HANDLE Privs;
		unsigned long AuthnLevel;
		unsigned long AuthnSvc;
		unsigned long AuthzSvc;
		status = RpcBindingInqAuthClient(nullptr, &Privs, nullptr, &AuthnLevel, &AuthnSvc, &AuthzSvc);
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

	if (szStringUuid != nullptr) RpcStringFree(&szStringUuid);
	return eventParams;
}

void rpcFunctionVerboseOutput(bool allowCall, const RpcEventParameters& eventParams)
{
	std::wstringstream wss;

	wss << (allowCall ? _T("Allowed") : _T("Blocked")) << _T(",");
	wss << eventParams.functionName + _T(",");
	wss << eventParams.uuidString << _T(",");
	wss << eventParams.OpNum << _T(",");
	wss << eventParams.endpoint << _T(",");
	wss << eventParams.sourceAddress << _T(",");
	wss << eventParams.clientName << _T(",");
	wss << eventParams.authnLevel << _T(",");
	wss << eventParams.authnSvc;

	WRITE_DEBUG_MSG(wss.str());
}

unsigned short getAddressAndPortFromBuffer(std::wstring& srcAddr, byte* buff)
{
	sockaddr* sockAddr = (sockaddr*)(buff);
	wchar_t outStr[0x80] = { 0 };

	PCWSTR addrPtr = nullptr;
	unsigned short port = 0;

	wchar_t uareshort[20] = { 0 };
	std::wstring msg = _T("address: ");

	switch (sockAddr->sa_family)
	{
	case AF_INET:
		addrPtr = InetNtop(sockAddr->sa_family, &(((struct sockaddr_in*)sockAddr)->sin_addr), outStr, 0x80);
		port = _byteswap_ushort(((struct sockaddr_in*)sockAddr)->sin_port);
		
		msg += addrPtr;
		msg += _T(" port: ");
		msg += std::to_wstring(port);
		WRITE_DEBUG_MSG(msg);
		break;
	case AF_INET6:
		addrPtr = InetNtop(sockAddr->sa_family, &(((struct sockaddr_in6*)sockAddr)->sin6_addr), outStr, 0x80);
		port = _byteswap_ushort(((struct sockaddr_in6*)sockAddr)->sin6_port);
		break;
	default:
		WRITE_DEBUG_MSG_WITH_STATUS(_T("Unknown address family type"), sockAddr->sa_family);
		break;
	}

	srcAddr = addrPtr;
	return port;
}

bool processRPCCallInternal(wchar_t* functionName, PRPC_MESSAGE pRpcMsg)
{
	RpcCallPolicy policy{};

	try
	{
		RpcBindingWrapper serverBinding;
		RPC_STATUS status = RpcBindingServerFromClient(0, &serverBinding.binding);
		if (status != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_STATUS(_T("RpcBindingServerFromClient failed"), status);
			return true;
		}

		RpcStringWrapper szStringBinding;
		status = RpcBindingToStringBinding(serverBinding.binding, szStringBinding.getRpcPtr());
		if (status != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_STATUS(_T("RpcBindingToStringBinding failed"), status);
			return true;
		}

		// Consider only calls over network transports
		if (_tcsstr(szStringBinding.str, _T("ncalrpc")) != nullptr)
		{
			return true;
		}

		RpcStringWrapper szStringBindingServer;
		status = RpcBindingToStringBinding(pRpcMsg->Handle, szStringBindingServer.getRpcPtr());
		if (status != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_STATUS(_T("Could not extract server endpoint via RpcBindingToStringBinding"), status);
		}

		const wchar_t* procName = L"RPC-Server.exe";
		byte buffSrc[0x80] = {0};
		unsigned long buffersize = 0x80;

		std::wstring srcAddrFromConnection;
		unsigned short srcPort = 0;

		status = I_RpcServerInqRemoteConnAddress(pRpcMsg->Handle, &buffSrc, &buffersize, (unsigned long*)&procName);
		if (status != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_STATUS(_T("Could not extract client address via I_RpcServerInqRemoteConnAddress"), status);
		}
		else
		{
			srcPort = getAddressAndPortFromBuffer(srcAddrFromConnection, buffSrc);
		}

		byte buffDst[0x80] = { 0 };
		std::wstring dstAddrFromConnection;
		unsigned short dstPort = 0;

		status = I_RpcServerInqLocalConnAddress(pRpcMsg->Handle, &buffDst, &buffersize, (unsigned long*)&procName);
		if (status != RPC_S_OK)
		{
			WRITE_DEBUG_MSG_WITH_STATUS(_T("Could not extract server address via I_RpcServerInqRemoteConnAddress"), status);
		}
		else
		{
			dstPort = getAddressAndPortFromBuffer(dstAddrFromConnection, buffDst);
		}

		const RpcEventParameters eventParams = populateEventParameters(pRpcMsg, szStringBindingServer.str, szStringBinding.str, functionName, srcAddrFromConnection, srcPort, dstAddrFromConnection, dstPort);
		
		policy = getMatchingPolicy(eventParams);

		if (verbose)
		{
			rpcFunctionVerboseOutput(policy.allow, eventParams);
		}

		if (policy.audit)
		{
			rpcFunctionCalledEvent(policy.allow, eventParams);
		}
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

	return policy.allow;
}

void processRPCCall(wchar_t* functionName, PRPC_MESSAGE pRpcMsg)
{
	const bool allowCall = processRPCCallInternal(functionName, pRpcMsg);
	
	if (!allowCall)
	{
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
