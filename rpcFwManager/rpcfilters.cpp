#include <ws2tcpip.h>
#include <Windows.h>
#include <NTSecAPI.h>
#include <fwpmu.h>
#include <sddl.h>
#include <rpc.h>
#include <stdio.h>
#include "stdafx.h"
#include "rpcfilters.h"

#pragma comment(lib, "Ws2_32.lib")

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
		}
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
			FwpmEngineClose0(engineH);
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

void installRPCFWProvider()
{
	installGenericProvider(&RPCFWProviderGUID, providerName.c_str(), &RPCFWSublayerGUID,sublayerName.c_str());
}

void enableAuditingForRPCFilters()
{
	updateAuditingForRPCFilters(3);
}

void disableAuditingForRPCFilters()
{
	updateAuditingForRPCFilters(4);
}

void addIPv4Filter(HANDLE eh, const char* remoteIP, GUID layerkey)
{
	FWPM_FILTER0			fwpFilter;
	DWORD					result = ERROR_SUCCESS;
	FWPM_FILTER_CONDITION0	fwpConditionIPv4;
	UINT32					ipv4;

	inet_pton(AF_INET, remoteIP, &ipv4);

	ZeroMemory(&fwpConditionIPv4, sizeof(fwpConditionIPv4));
	fwpConditionIPv4.matchType = FWP_MATCH_EQUAL;
	fwpConditionIPv4.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS_V4;
	fwpConditionIPv4.conditionValue.type = FWP_UINT32;
	fwpConditionIPv4.conditionValue.uint32 = ipv4;

	ZeroMemory(&fwpFilter, sizeof(fwpFilter));
	fwpFilter.layerKey = layerkey;
	fwpFilter.action.type = FWP_ACTION_BLOCK;
	fwpFilter.weight.type = FWP_EMPTY; 
	fwpFilter.numFilterConditions = 1;
	fwpFilter.displayData.name = (wchar_t*)L"RPC filter block ip";
	fwpFilter.displayData.description = (wchar_t*)L"Filter to block all inbound connections from an ip";
	fwpFilter.filterCondition = &fwpConditionIPv4;
	fwpFilter.providerKey = &RPCFWProviderGUID;

	fwpFilter.subLayerKey = FWPM_SUBLAYER_RPC_AUDIT;
	fwpFilter.rawContext = 1; 
	fwpFilter.flags = FWPM_FILTER_FLAG_PERSISTENT;

	printf("Adding filter\n");
	result = FwpmFilterAdd0(eh, &fwpFilter, NULL, NULL);

	if (result != ERROR_SUCCESS)
		printf("FwpmFilterAdd0 failed. Return value: %x.\n", result);
	else
		printf("Filter added successfully.\n");
}

HANDLE openFwEngineHandle()
{
	FWPM_SESSION0	session;
	HANDLE engineHandle;
	DWORD			result = ERROR_SUCCESS;
	TCHAR			sessionKey[39];

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
		_tprintf(_T("Call to FwpmEngineOpen failed: %x"), result);
	}
	else
	{
		_tprintf(_T("Filter engine opened successfully.\n"));
	}

	return engineHandle;
}

void createIPBlockRPCFilter(std::string &ipAddressStr)
{
	FwHandleWrapper engineHandle;
	engineHandle.h = openFwEngineHandle();
	if (engineHandle.h == nullptr)
	{
		return;
	}
	addIPv4Filter(engineHandle.h, ipAddressStr.c_str(), FWPM_LAYER_RPC_UM);
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
	HANDLE engineHandle = openFwEngineHandle();

	if (engineHandle != nullptr)
	{
		EnumHandleWrapper ehw = {0};
		ehw.engineH = engineHandle;
		ehw.enumH = returnEnumHandleToAllRPCFilters(engineHandle);
		
		if (ehw.enumH != nullptr)
		{
			FWPM_FILTER0** entries;
			unsigned int numEntries;

			DWORD ret = FwpmFilterEnum(ehw.engineH, ehw.enumH, 1, &entries, &numEntries);
			if (ret != ERROR_SUCCESS)
			{
				_tprintf(_T("Enum filters failed: 0x%x\n"), ret);
				return;
			}

			for (int entryNum = 0; entryNum < numEntries; entryNum++)
			{
				ret = FwpmFilterDeleteById0(engineHandle, entries[entryNum]->filterId);
				if (ret == ERROR_SUCCESS)
				{
					_tprintf(_T("Removed filter: %s\n"), entries[entryNum]->displayData.description);
				}
				else
				{
					_tprintf(_T("Falied to remove filter: %s : 0x%x\n"), entries[entryNum]->displayData.description, ret);
				}
			}
		}
	}
}