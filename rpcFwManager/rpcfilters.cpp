#include <ws2tcpip.h>
#include <Windows.h>
#include <NTSecAPI.h>
#include <fwpmu.h>
#include <sddl.h>
#include <rpc.h>
#include <stdio.h>
#include "stdafx.h"
#include "rpcfilters.h"
#include <accctrl.h>
#include <aclapi.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <array>

#pragma comment(lib, "Ws2_32.lib")

typedef std::vector<FWPM_FILTER_CONDITION0> conditionsVector;

GUID RPCFWProviderGUID = { 0x17171717,0x1717,0x1717,{0x17,0x17,0x17,0x17,0x17,0x17,0x17,0x17} };
std::wstring providerName = std::wstring(L"RPCFW");

GUID RPCFWSublayerGUID = { 0x77777777,0x1717,0x1717,{0x17,0x17,0x17,0x17,0x17,0x17,0x17,0x17} };
std::wstring sublayerName = std::wstring(L"RPCFWSublayer");

struct FwHandleWrapper
{
	~FwHandleWrapper()
	{
		if (h != nullptr)
		{
			FwpmEngineClose0(h);
			h = nullptr;
		}
	}
	FwHandleWrapper& operator=(FwHandleWrapper&& const other)
	{
		h = std::move(other.h);
		return *this;
	}

	HANDLE h = nullptr;
};

struct EnumHandleWrapper
{
	~EnumHandleWrapper()
	{
		if (enumH != nullptr)
		{
			FwpmFilterDestroyEnumHandle0(engineH,enumH);
			HANDLE engineH = nullptr;
			HANDLE enumH = nullptr;
		}
	}

	HANDLE engineH = nullptr;
	HANDLE enumH = nullptr;
};

void updateAuditingForRPCFilters(unsigned long auditingInformation)
{
	// Audit_DetailedTracking
	std::wstring categoryGUIDString(L"{6997984C-797A-11D9-BED3-505054503030}");
	
	GUID catagoryGUID;

	HRESULT res = CLSIDFromString(categoryGUIDString.c_str(), &catagoryGUID);
	if (res != S_OK)
	{
		_tprintf(_T("Could not convert audit category from string: %d\n"), res);
		return;
	}
	
	// Audit_DetailedTracking_RpcCall
	std::wstring subcategoryGUIDString(L"{0CCE922E-69AE-11D9-BED3-505054503030}");
	GUID subCategoryGUID;

	res = CLSIDFromString(subcategoryGUIDString.c_str(), &subCategoryGUID);
	if (res != S_OK)
	{
		_tprintf(_T("Could not convert audit sub-category from string: %d\n"), res);
		return;
	}
	AUDIT_POLICY_INFORMATION api[1];
	api[0].AuditCategoryGuid = catagoryGUID;
	api[0].AuditSubCategoryGuid = subCategoryGUID;
	api[0].AuditingInformation = auditingInformation;
	
	if (!AuditSetSystemPolicy(api, 1))
	{
		_tprintf(_T("Error, could set system policy: %d\n"), GetLastError());
	}
	else
	{
		_tprintf(_T("Updated rpc filter auditing state.\n"));
	}
}

bool isAuditingEnabledForRPCFilters()
{
	// Audit_DetailedTracking
	std::wstring categoryGUIDString(L"{6997984C-797A-11D9-BED3-505054503030}");

	GUID catagoryGUID;

	HRESULT res = CLSIDFromString(categoryGUIDString.c_str(), &catagoryGUID);
	if (res != S_OK)
	{
		_tprintf(_T("Could not convert audit category from string: %d\n"), res);
		return false;
	}

	// Audit_DetailedTracking_RpcCall
	std::wstring subcategoryGUIDString(L"{0CCE922E-69AE-11D9-BED3-505054503030}");
	GUID subCategoryGUID;

	res = CLSIDFromString(subcategoryGUIDString.c_str(), &subCategoryGUID);
	if (res != S_OK)
	{
		_tprintf(_T("Could not convert audit sub-category from string: %d\n"), res);
		return false;
	}

	PAUDIT_POLICY_INFORMATION api = nullptr;
	if (!AuditQuerySystemPolicy(&subCategoryGUID, 1, &api))
	{
		_tprintf(_T("Error calling AuditQuerySystemPolicy: %d\n"), GetLastError());
		return false;
	}

	if (api->AuditingInformation == 0) return false;

	return true;
}

void installGenericProvider(
	__in const GUID* providerKey,
	__in PCWSTR providerName,
	__in const GUID* subLayerKey,
	__in PCWSTR subLayerName
)
{
	DWORD result = ERROR_SUCCESS;
	FwHandleWrapper engine;
	FWPM_SESSION0 session;
	FWPM_PROVIDER0 provider;
	FWPM_SUBLAYER0 subLayer;

	memset(&session, 0, sizeof(session));
	// The session name isn't required but may be useful for diagnostics.
	std::wstring sName = std::wstring(L"RPCFW_Installer_Session");
	session.displayData.name = (wchar_t*)sName.c_str();
	// Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
	// errors while waiting to acquire the transaction lock.
	session.txnWaitTimeoutInMSec = INFINITE;

	// The authentication service should always be RPC_C_AUTHN_DEFAULT.
	result = FwpmEngineOpen0(
		NULL,
		RPC_C_AUTHN_DEFAULT,
		NULL,
		&session,
		&engine.h
	);
	if (result != ERROR_SUCCESS)
	{
		_tprintf(_T("Call to FwpmEngineOpen failed: 0x%x"), result);
		return;
	}

	// We add the provider and sublayer from within a single transaction to make
	// it easy to clean up partial results in error paths.
	result = FwpmTransactionBegin0(engine.h, 0);
	if (result != ERROR_SUCCESS)
	{
		_tprintf(_T("Call to FwpmTransactionBegin0 failed: 0x%x"), result);
		return;
	}

	memset(&provider, 0, sizeof(provider));
	provider.providerKey = *providerKey;
	provider.displayData.name = (PWSTR)providerName;
	provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

	result = FwpmProviderAdd0(engine.h, &provider, NULL);
	if ((result != FWP_E_ALREADY_EXISTS) && (result != ERROR_SUCCESS))
	{
		_tprintf(_T("Call to FwpmProviderAdd0 failed: 0x%x"), result);
		return;
	}

	memset(&subLayer, 0, sizeof(subLayer));
	subLayer.subLayerKey = *subLayerKey;
	subLayer.displayData.name = (PWSTR)subLayerName;
	subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
	subLayer.providerKey = (GUID*)providerKey;
	subLayer.weight = 0x8000;

	result = FwpmSubLayerAdd0(engine.h, &subLayer, NULL);
	if ((result != FWP_E_ALREADY_EXISTS) && (result != ERROR_SUCCESS))
	{
		_tprintf(_T("Call to FwpmSubLayerAdd0 failed: 0x%x"), result);
		return;
	}

	// Once all the adds have succeeded, we commit the transaction to persist
	// the new objects.
	result = FwpmTransactionCommit0(engine.h);
	if ((result != FWP_E_ALREADY_EXISTS) && (result != ERROR_SUCCESS))
	{
		_tprintf(_T("Call to FwpmTransactionCommit0 failed: 0x%x"), result);
		return;
	}

}


bool isProviderInstalled(__in const GUID* providerKey)
{
	DWORD result = ERROR_SUCCESS;
	FwHandleWrapper engine;
	FWPM_SESSION0 session;
	FWPM_PROVIDER_CONTEXT3** providerContext = nullptr;
	FWPM_SUBLAYER0 subLayer;

	memset(&session, 0, sizeof(session));
	// The session name isn't required but may be useful for diagnostics.
	std::wstring sName = std::wstring(L"RPCFW_Checker_Session");
	session.displayData.name = (wchar_t*)sName.c_str();
	// Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
	// errors while waiting to acquire the transaction lock.
	session.txnWaitTimeoutInMSec = INFINITE;

	// The authentication service should always be RPC_C_AUTHN_DEFAULT.
	result = FwpmEngineOpen0(
		NULL,
		RPC_C_AUTHN_DEFAULT,
		NULL,
		&session,
		&engine.h
	);
	if (result != ERROR_SUCCESS)
	{
		_tprintf(_T("Call to FwpmEngineOpen failed: 0x%x"), result);
		return false;
	}

	/*result = FwpmTransactionBegin0(engine.h, 0);
	if (result != ERROR_SUCCESS)
	{
		_tprintf(_T("Call to FwpmTransactionBegin0 failed: 0x%x"), result);
		return false;
	}*/

	result = FwpmProviderContextGetByKey(engine.h, providerKey, providerContext);
	if (result != ERROR_SUCCESS)
	{
		return false;
	}
	FwpmFreeMemory0((void**)providerContext);
	return true;

}

bool isProviderInstalled()
{
	return isProviderInstalled(&RPCFWProviderGUID);
}

void installRPCFWProvider()
{
	installGenericProvider(&RPCFWProviderGUID, providerName.c_str(), &RPCFWSublayerGUID, sublayerName.c_str());

}

void setLocalRPCSecurityPolicyInReg(unsigned long auditInformation)
{
	unsigned long auditInfo = auditInformation;
	HKEY    hRegKey = nullptr;
	// Create RPC policy registry key
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_READ | KEY_WRITE | KEY_SET_VALUE, nullptr, &hRegKey, nullptr) != ERROR_SUCCESS)
	{
		_tprintf(TEXT("ERROR: Couldn't create RPC policy registry key: [%d].\n"), GetLastError());
		return;
	}

	// Set RPC audit information
	if (RegSetValueEx(hRegKey, _T("StateInformation"), 0, REG_DWORD, (LPBYTE)&auditInfo, sizeof(auditInfo)) != ERROR_SUCCESS)
	{
		_tprintf(TEXT("ERROR: setting value to StateInformation failed: [%d].\n"), GetLastError());
	}

	RegCloseKey(hRegKey);
}

void writeAuditFile()
{
	wchar_t  destPath[INFO_BUFFER_SIZE];
	if (!GetSystemDirectory(destPath, INFO_BUFFER_SIZE))
	{
		_tprintf(TEXT("ERROR: Couldn't get the system directory [%d].\n"), GetLastError());
		return;
	}

	std::wstring destPathStr = destPath;
	destPathStr += TEXT("\\GroupPolicy\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv");

	std::ofstream auditFileStream(destPathStr);
	if (auditFileStream.bad())
	{
		_tprintf(TEXT("ERROR: Couldn't open audit file for writing [%s].\n"), destPathStr);
		return;
	}

	auditFileStream << "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\n, System, Audit RPC Events, {0cce922e-69ae-11d9-bed3-505054503030 },Success and Failure, ,3" << std::endl;
	auditFileStream.close();
}

void enableAuditingForRPCFilters()
{
	updateAuditingForRPCFilters(3);
	setLocalRPCSecurityPolicyInReg(3);
	writeAuditFile();
}

void disableAuditingForRPCFilters()
{
	updateAuditingForRPCFilters(4);
	setLocalRPCSecurityPolicyInReg(4);
}

FWP_BYTE_ARRAY16* allocateFWPByteArray16(const BYTE* byteArray)
{
	FWP_BYTE_ARRAY16* byteArrayPtr = static_cast<FWP_BYTE_ARRAY16*>(malloc(sizeof(FWP_BYTE_ARRAY16)));
	if (byteArrayPtr)
	{
		memcpy(byteArrayPtr->byteArray16, byteArray, sizeof(byteArrayPtr->byteArray16));
	}

	return byteArrayPtr;
}

FWPM_FILTER_CONDITION0 createSDCondition(const std::wstring& sidString)
{
	FWPM_FILTER_CONDITION0 sidCondition = { 0 };
	FWP_BYTE_BLOB* blob;
	PSECURITY_DESCRIPTOR psd;

	unsigned long sdsize = 0;

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sidString.c_str(), SDDL_REVISION_1, &psd, &sdsize))
	{
		_tprintf(_T("Failed to convert SD from string: %d\n"), GetLastError());
	}

	blob = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
	blob->size = sdsize;
	blob->data = (UINT8*)psd;

	sidCondition.matchType = FWP_MATCH_EQUAL;
	sidCondition.fieldKey = FWPM_CONDITION_REMOTE_USER_TOKEN;
	sidCondition.conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
	sidCondition.conditionValue.sd = blob;

	return sidCondition;
}

FWPM_FILTER_CONDITION0 createSIDCondition(const std::wstring& sidString)
{
	std::wstring SDString = L"D:(A;;CC;;;" + sidString + L")";

	return createSDCondition(SDString);
}

FWPM_FILTER_CONDITION0 createUUIDCondition(std::wstring& uuidString)
{
	FWPM_FILTER_CONDITION0 uuidCondition = {0};
	UUID interfaceUUID;

	RPC_STATUS ret = UuidFromString((RPC_WSTR)uuidString.c_str(), &interfaceUUID);
	if (ret != RPC_S_OK)
	{
		_tprintf(_T("Failed to convert UUID:%s from string: %d\n"), uuidString,ret);
	}

	FWP_BYTE_ARRAY16* allocatedBA16 = allocateFWPByteArray16((BYTE*) & interfaceUUID);

	uuidCondition.matchType = FWP_MATCH_EQUAL;
	uuidCondition.fieldKey = FWPM_CONDITION_RPC_IF_UUID;
	uuidCondition.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
	uuidCondition.conditionValue.byteArray16 = allocatedBA16;

	return uuidCondition;
}

FWPM_FILTER_CONDITION0 createProtocolCondition(std::wstring& protocol)
{
	std::transform(protocol.begin(), protocol.end(), protocol.begin(), ::tolower);
	FWPM_FILTER_CONDITION0 protoclCondition = { 0 };
	unsigned int uintProtocl = 0;

	protoclCondition.matchType = FWP_MATCH_EQUAL;

	if (protocol.find(_T("ncacn_ip_tcp")) != std::string::npos)
	{
		uintProtocl = RPC_PROTSEQ_TCP;
	}
	else if ((protocol.find(_T("ncacn_np")) != std::string::npos))
	{
		uintProtocl = RPC_PROTSEQ_NMP;
	}
	else if (protocol.find(_T("ncacn_http")) != std::string::npos)
	{
		uintProtocl = RPC_PROTSEQ_HTTP;
	}
	else if (protocol.find(_T("remote")) != std::string::npos)
	{
		uintProtocl = RPC_PROTSEQ_LRPC;
		protoclCondition.matchType = FWP_MATCH_NOT_EQUAL;
	}
	else if (protocol.find(_T("ncalrpc")) != std::string::npos)
	{
		_tprintf(_T("Unknown protocl found in configutaion: %s\n"), protocol);
		uintProtocl = RPC_PROTSEQ_LRPC;
	}
	else return protoclCondition;
		
	protoclCondition.fieldKey = FWPM_CONDITION_RPC_PROTOCOL;
	protoclCondition.conditionValue.type = FWP_UINT8;
	protoclCondition.conditionValue.uint8 = uintProtocl;

	return protoclCondition;
}

bool isIpv4Addr(std::wstring& testIp)
{
	UINT32 ipv4;

 	if (InetPton(AF_INET, testIp.c_str(), &ipv4) <= 0) return false;

	return true;
}

bool isIPv4CIDR(std::wstring& testIp)
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
	if (!isIpv4Addr(ipOnly) ||  prefixLength > 32)
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

bool isIPv6CIDR(std::wstring& testIp)
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

UINT32 generateBitMask(UINT32 numOfBits) {
	UINT32 bitmask;

	bitmask = (~((1 << (32 - numOfBits)) - 1));


	return bitmask;
}

FWPM_FILTER_CONDITION0 createIPv4Condition(std::wstring &remoteIP)
{
	FWPM_FILTER_CONDITION0	ipv4Condition = {0};
	UINT32 ipv4;

	InetPton(AF_INET, remoteIP.c_str(), &ipv4);

	ipv4Condition.matchType = FWP_MATCH_EQUAL;
	ipv4Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS_V4;
	ipv4Condition.conditionValue.type = FWP_UINT32;
	ipv4Condition.conditionValue.uint32 = ipv4;

	return ipv4Condition;
}

FWPM_FILTER_CONDITION0 createIPv4CIDRCondition(std::wstring& remoteIPCIDR)
{
	std::wstring ipv4;
	unsigned int prefixLength;

	size_t slashPos = remoteIPCIDR.find(L"/");
	prefixLength = std::stoi(remoteIPCIDR.substr(slashPos + 1));
	ipv4 = remoteIPCIDR.substr(0, slashPos);

	UINT32 ipv4Int = 0;
	UINT32 bitmask = generateBitMask(prefixLength);
	InetPton(AF_INET, ipv4.c_str(), &ipv4Int);

	UINT32 ipv4IntHostOrder = ntohl(ipv4Int);
	
	FWPM_FILTER_CONDITION0	ipv4Condition = { 0 };

	ipv4Condition.matchType = FWP_MATCH_EQUAL;
	ipv4Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS_V4;
	ipv4Condition.conditionValue.type = FWP_V4_ADDR_MASK;
	ipv4Condition.conditionValue.v4AddrMask = new FWP_V4_ADDR_AND_MASK;
	ipv4Condition.conditionValue.v4AddrMask->addr = ipv4IntHostOrder;
	ipv4Condition.conditionValue.v4AddrMask->mask = bitmask;
	
	return ipv4Condition;
}

struct ipv6Struct
{
	UINT8 addr[16];
};

void createMinIPv6(std::array<UINT8,16> &ipv6, int maskLength) {

	int fullBlocks = maskLength / 16;
	int remainingBits = maskLength % 16;

	for (int i = fullBlocks + 1; i < 8; ++i) {
		ipv6[i] = 0;
	}

	int mask = (1 << (16 - remainingBits)) - 1;
	ipv6[fullBlocks] &= ~mask;
}

void createMaxIPv6(std::array<UINT8, 16> &ipv6, int maskLength) {

	int fullBlocks = maskLength / 16;
	int remainingBits = maskLength % 16;

	for (int i = fullBlocks + 1; i < 8; ++i) {
		ipv6[i] = 0xFF;
	}

	int mask = (1 << (16 - remainingBits)) - 1;
	ipv6[fullBlocks] |= mask;

}

bool getMinMaxAddressesIpv6(const std::wstring& ipAddress) {
	size_t slashPos = ipAddress.find(L"/");
	if (slashPos == std::string::npos) {
		return false;
	}

	unsigned int prefixLength;

	try {
		prefixLength = std::stoi(ipAddress.substr(slashPos + 1));
	}
	catch (const std::exception&) {
		return false;
	}

	std::wstring ipOnly = ipAddress.substr(0, slashPos);
	if (!isIpv6Address(ipOnly) || prefixLength > 128)
	{
		return false;
	}
	
	std::array<UINT8, 16> ipv6ArrayMin;
	std::array<UINT8, 16> ipv6ArrayMax;

	UINT8 ipv6arr[16];

	if (InetPton(AF_INET6, ipOnly.c_str(), ipv6arr) != 1) {
		throw std::invalid_argument("Invalid IPv6 address");
	}

	for (int i = 0; i < 16; i++) ipv6ArrayMax[i] = ipv6ArrayMin[i] = ipv6arr[i];

	createMinIPv6(ipv6ArrayMin, prefixLength);

	return true;
}


FWPM_FILTER_CONDITION0 createIPv6CIDRCondition(const std::wstring& remoteIPCIDR)
{
	getMinMaxAddressesIpv6(remoteIPCIDR);
	std::wstring ipv6;
	unsigned int prefixLength;

	size_t slashPos = remoteIPCIDR.find(L"/");
	prefixLength = std::stoi(remoteIPCIDR.substr(slashPos + 1));
	ipv6 = remoteIPCIDR.substr(0, slashPos);

	FWPM_FILTER_CONDITION0 ipv6Condition = { 0 };

	ipv6Condition.matchType = FWP_MATCH_EQUAL;
	ipv6Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS_V6;
	ipv6Condition.conditionValue.type = FWP_V6_ADDR_MASK;
	ipv6Condition.conditionValue.v6AddrMask = new FWP_V6_ADDR_AND_MASK;
	InetPton(AF_INET6, ipv6.c_str(), ipv6Condition.conditionValue.v6AddrMask->addr);
	ipv6Condition.conditionValue.v6AddrMask->prefixLength;

	return ipv6Condition;
}

FWPM_FILTER_CONDITION0 createIPv6Condition(const std::wstring& remoteIP)
{
	FWPM_FILTER_CONDITION0 ipv6Condition = { 0 };
	FWP_BYTE_ARRAY16 fwpBA16;

	InetPton(AF_INET6, remoteIP.c_str(), &(fwpBA16.byteArray16));

	FWP_BYTE_ARRAY16* allocatedBA16 = allocateFWPByteArray16(fwpBA16.byteArray16);

	ipv6Condition.matchType = FWP_MATCH_EQUAL;
	ipv6Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS_V6;
	ipv6Condition.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
	ipv6Condition.conditionValue.byteArray16 = allocatedBA16;

	return ipv6Condition;
}

FWPM_FILTER_CONDITION0 createEffectivelyAnyCondition()
{
	FWPM_FILTER_CONDITION0 uuidCondition = { 0 };

	uuidCondition.matchType = FWP_MATCH_GREATER_OR_EQUAL;
	uuidCondition.fieldKey = FWPM_CONDITION_RPC_IF_VERSION;
	uuidCondition.conditionValue.type = FWP_UINT16;
	uuidCondition.conditionValue.uint16 = 0;

	return uuidCondition;
}

HANDLE openFwEngineHandle()
{
	FWPM_SESSION0	session;
	HANDLE engineHandle;
	DWORD			result = ERROR_SUCCESS;

	ZeroMemory(&session, sizeof(session));
	session.kernelMode = FALSE;
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	result = FwpmEngineOpen0(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&engineHandle);

	if (result != ERROR_SUCCESS)
	{
		_tprintf(_T("Call to FwpmEngineOpen failed: %x\n"), result);
	}

	return engineHandle;
}

void createRPCFilterFromConfigLine( LineConfig confLine, std::wstring &filterName, std::wstring &filterDescription, unsigned long long weight)
{
	FwHandleWrapper fwhw; 
	fwhw.h = openFwEngineHandle();
	conditionsVector conditions;

	bool existsSourceAddr = false;
	bool existsUUID = false;
	bool anyFilter = false;

	if (confLine.min_addr.has_value())
	{
		if (isIpv4Addr(confLine.min_addr.value()))
		{
			existsSourceAddr = true;
			conditions.push_back(createIPv4Condition(confLine.min_addr.value()));
		}
		else if (isIpv6Address(confLine.min_addr.value()))
		{
			existsSourceAddr = true;
			conditions.push_back(createIPv6Condition(confLine.min_addr.value()));
		}
		else if (isIPv4CIDR(confLine.min_addr.value()))
		{
			conditions.push_back(createIPv4CIDRCondition(confLine.min_addr.value()));
			_tprintf(_T("WARNING: CIDR ranges in Filters are highly unreliable: %s.\n"), filterDescription.c_str());
		}
		else if (isIPv6CIDR(confLine.min_addr.value()))
		{
			conditions.push_back(createIPv6CIDRCondition(confLine.min_addr.value()));
			_tprintf(_T("WARNING: CIDR ranges in Filters are highly unreliable: %s.\n"), filterDescription.c_str());
		}
		else
		{
			_tprintf(_T("Malformed address: %s\n"), confLine.min_addr);
		}
		
	}
	if (confLine.uuid.has_value())
	{
		existsUUID = true;
		conditions.push_back(createUUIDCondition(confLine.uuid.value()));
	}
	if (confLine.sid.has_value())
	{
		conditions.push_back(createSIDCondition(confLine.sid.value()));
	}
	if (confLine.protocol.has_value())
	{
		conditions.push_back(createProtocolCondition(confLine.protocol.value()));
	}
	if (conditions.size() == 0)
	{
		anyFilter = true;
		// An "ANY" condition may cause faults with certain RPC services.
		//conditions.push_back(createEffectivelyAnyCondition());
	}

	FWPM_FILTER0 fwpFilter = {0};
		
	fwpFilter.layerKey = FWPM_LAYER_RPC_UM;
	fwpFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	fwpFilter.action.type = (confLine.policy.allow) ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
	fwpFilter.weight.type = FWP_UINT64;
	fwpFilter.weight.uint64 = &weight;
	fwpFilter.displayData.name = (wchar_t*)filterName.c_str();
	fwpFilter.displayData.description = (wchar_t*)filterDescription.c_str();
	fwpFilter.numFilterConditions = conditions.size();
	fwpFilter.flags = FWPM_FILTER_FLAG_PERSISTENT;
	fwpFilter.providerKey = &RPCFWProviderGUID;
	
	if (confLine.policy.audit)
	{
		fwpFilter.subLayerKey = FWPM_SUBLAYER_RPC_AUDIT;
		fwpFilter.rawContext = 1;

	}
	
	if (conditions.size() > 0)
	{
		fwpFilter.filterCondition = &conditions[0];
	}

	DWORD result = FwpmFilterAdd0(fwhw.h, &fwpFilter, nullptr, nullptr);

	if (result != ERROR_SUCCESS)
	{
		_tprintf(_T("FwpmFilterAdd0 failed. Return value: 0x%x.\n"), result);
		return;
	}

	if (!anyFilter && !existsUUID)
	{
		_tprintf(_T("WARNING: Filters without explicit UUIDs may cause faults: %s.\n"), filterDescription.c_str());
	}

	if (existsSourceAddr)
	{
		_tprintf(_T("WARNING: source address filters do not protect RPC traffic over named pipes: %s.\n"), filterDescription.c_str());
	}
}

void createRPCFilterFromTextLines(configLinesVector configsVector)
{
	if (configsVector.size() > 0)
	{
		unsigned int weight = 0x00FFFFFF;

		for (int i = 0; i < configsVector.size(); i++)
		{
			std::wstring confLineStr = configsVector[i].first;
			LineConfig confLine = configsVector[i].second;

			std::wstring filterName = L"RPC Filter " + std::to_wstring(i + 1);
			createRPCFilterFromConfigLine(confLine, filterName, confLineStr, weight--);
		}
	}
}

HANDLE returnEnumHandleToAllRPCFilters(HANDLE eh)
{
	FWPM_FILTER_ENUM_TEMPLATE0 fwEnumTemplate = {0};

	fwEnumTemplate.providerKey = &RPCFWProviderGUID;
	fwEnumTemplate.layerKey = FWPM_LAYER_RPC_UM;

	fwEnumTemplate.enumType = FWP_FILTER_ENUM_OVERLAPPING;
	fwEnumTemplate.flags = FWP_FILTER_ENUM_FLAG_SORTED;
	fwEnumTemplate.providerContextTemplate = nullptr;
	fwEnumTemplate.numFilterConditions = 0;
	fwEnumTemplate.filterCondition = nullptr;
	fwEnumTemplate.actionMask = 0xFFFFFFFF;
	fwEnumTemplate.calloutKey = nullptr;
	

	HANDLE enumHandle = nullptr; 

	DWORD ret = FwpmFilterCreateEnumHandle(eh, &fwEnumTemplate, &enumHandle);
	if (ret != ERROR_SUCCESS)
	{
		_tprintf(_T("Could not enum RPC filters: 0x%x\n"), ret);
	}

	return enumHandle;
}

void deleteAllRPCFilters()
{
	FwHandleWrapper fwhw;
	fwhw.h = openFwEngineHandle();

	if (fwhw.h != nullptr)
	{
		EnumHandleWrapper ehw = {0};
		ehw.engineH = fwhw.h;
		ehw.enumH = returnEnumHandleToAllRPCFilters(fwhw.h);
		
		if (ehw.enumH != nullptr)
		{
			FWPM_FILTER0** entries;
			unsigned int numEntries;

			DWORD ret = FwpmFilterEnum(ehw.engineH, ehw.enumH, 0xFFFF, &entries, &numEntries);
			if (ret != ERROR_SUCCESS)
			{
				_tprintf(_T("Enum filters failed: 0x%x\n"), ret);
				return;
			}

			for (unsigned int entryNum = 0; entryNum < numEntries; entryNum++)
			{
				ret = FwpmFilterDeleteById0(fwhw.h, entries[entryNum]->filterId);
				if (ret != ERROR_SUCCESS)
				{
					_tprintf(_T("Falied to remove filter: %s : 0x%x\n"), entries[entryNum]->displayData.description, ret);
				}
			}
		}
	}
}

void printAllRPCFilters()
{
	FwHandleWrapper engineHandle;
	engineHandle.h = openFwEngineHandle();

	if (engineHandle.h != nullptr)
	{
		EnumHandleWrapper ehw = { 0 };
		ehw.engineH = engineHandle.h;
		ehw.enumH = returnEnumHandleToAllRPCFilters(engineHandle.h);

		if (ehw.enumH != nullptr)
		{
			FWPM_FILTER0** entries;
			unsigned int numEntries;

			DWORD ret = FwpmFilterEnum(ehw.engineH, ehw.enumH, 0xFFFF, &entries, &numEntries);
			if (ret != ERROR_SUCCESS)
			{
				_tprintf(_T("Enum filters failed: 0x%x\n"), ret);
				return;
			}

			if (numEntries == 0)
			{
				_tprintf(L"\tNo relevant RPC Filters found!\n");
			}

			for (unsigned int entryNum = 0; entryNum < numEntries; entryNum++)
			{
				std::wstring entry = entries[entryNum]->displayData.description;
				std::replace(entry.begin(), entry.end(), L'\r', L'\0');
				_tprintf(L"\t");
				_tprintf(entry.c_str());
				_tprintf(L"\n");
			}
		}
	}
}