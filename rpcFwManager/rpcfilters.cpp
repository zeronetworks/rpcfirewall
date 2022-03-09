#include "stdafx.h"
#include "rpcfilters.h"
#include <Windows.h>
#include <NTSecAPI.h>

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

void enableAuditingForRPCFilters()
{
	updateAuditingForRPCFilters(3);
}

void disableAuditingForRPCFilters()
{
	updateAuditingForRPCFilters(4);
}