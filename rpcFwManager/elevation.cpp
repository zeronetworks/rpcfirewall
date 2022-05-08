#include "stdafx.h"
#include "elevation.h"


HANDLE getAccessToken(DWORD pid, DWORD desiredAccess)
{
	/* Retrieves an access token for a process */
	HANDLE currentProcess = {};
	HANDLE AccessToken = {};
	DWORD LastError;
	try {
		if (pid == 0)
		{
			currentProcess = GetCurrentProcess();
		}
		else
		{
			currentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);
			if (!currentProcess)
			{
				LastError = GetLastError();
				_tprintf(TEXT("ERROR: OpenProcess %d(): %d\n"), pid,LastError);
				return nullptr;
			}
		}
		if (!OpenProcessToken(currentProcess, desiredAccess, &AccessToken))
		{
			LastError = GetLastError();
			_tprintf(TEXT("ERROR: OpenProcessToken %d: %d\n"), pid ,LastError);
			return nullptr;
		}
		return AccessToken;
	}
	catch (...) {
		LastError = GetLastError();
		_tprintf(TEXT("Exception during GetAccessToken(): %d\n"), GetLastError());
	}
	return nullptr;
}

DWORD getProcessIDFromName(wchar_t* procName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD pid = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, procName) == 0)
			{
				pid = entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return pid;

}

bool amISYSTEM()
{
	bool amisystem = false;

	HANDLE hToken;
	HANDLE hProcess;

	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = nullptr;
	DWORD dwIntegrityLevel;

	hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,dwLengthNeeded);
				if (pTIL != nullptr)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

						if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
						{
							// High Integrity
							amisystem = true;
						}
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
	}
	return amisystem;
}

bool setPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	bool bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		nullptr,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		_tprintf(TEXT("LookupPrivilegeValue error: %u\n"), GetLastError());
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		false,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)nullptr,
		(PDWORD)nullptr))
	{
		_tprintf(TEXT("AdjustTokenPrivileges error: %u\n"), GetLastError());
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		_tprintf(TEXT("The token does not have the specified privilege. \n"));
		return false;
	}

	return true;
}

bool setSecurityPrivilege(const wchar_t* privName)
{
	return setPrivilege(getAccessToken(0, TOKEN_ADJUST_PRIVILEGES), privName, true);
}

void tryAndRunElevated(DWORD pid)
{
	// Enable core privileges  
	if (!setSecurityPrivilege(TEXT("SeDebugPrivilege")))
	{
		_tprintf(TEXT("Could not get debug privileges!\n"));
		return;
	}

	if (!amISYSTEM())
	{
		// Retrieves the remote process token.
		HANDLE pToken = getAccessToken(pid, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
		if (pToken)
		{
			//These are required to call DuplicateTokenEx.
			SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;

			if (!ImpersonateLoggedOnUser(pToken))
			{
				_tprintf(TEXT("ERROR: Could not impersonate SYSTEM [%d]\n"), GetLastError());
				return;
			}

			wchar_t Imp_usrename[200];
			DWORD name_len = 200;
			GetUserName(Imp_usrename, &name_len);
			//_tprintf(TEXT("Running as: %s\n"), Imp_usrename);
		}
	}
}

void elevateCurrentProcessToSystem()
{
	wchar_t sysProcessName[] = TEXT("winlogon.exe");
	tryAndRunElevated(getProcessIDFromName(sysProcessName));
}
