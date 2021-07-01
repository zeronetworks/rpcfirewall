#include "rpcMessages.h"
#include "pch.h"
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include "Messages.h"
#include <tchar.h>
#include "rpcMessages.h"
#include <string>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")

#define PROVIDER_NAME TEXT("RPCFWP")
#define DLL_PATH TEXT("%SystemRoot%\\system32\\rpcMessages.dll")

HANDLE hEventLog = NULL;

BOOL compareCharCaseInsensitive(TCHAR c1, TCHAR c2)
{
    if (c1 == c2)
        return true;
    else if (std::toupper(c1) == std::toupper(c2))
        return true;
    return false;
}

BOOL compareStringsCaseinsensitive(TCHAR* str1, TCHAR* str2)
{
    TCHAR tcharEnd = _T("\0")[0];

    for (int i = 0; i < MAX_PATH; i++)
    {
        if ((str1[i] == tcharEnd) || (str2[i] == tcharEnd))
        {
            break;
        }

        if (!compareCharCaseInsensitive(str1[i], str2[i]))
        {
            return false;
        }
    }
    return true;
}

BOOL compareStringsCaseinsensitive(TCHAR* str1, TCHAR* str2, DWORD maxLen)
{
    TCHAR tcharEnd = _T("\0")[0];

    for (int i = 0; i < maxLen; i++)
    {
        if ((str1[i] == tcharEnd) || (str2[i] == tcharEnd))
        {
            break;
        }

        if (!compareCharCaseInsensitive(str1[i], str2[i]))
        {
            return false;
        }
    }
    return true;
}

BOOL regDelNodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
{
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    TCHAR szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS)
        return TRUE;

    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            _tprintf(_T("Registry key already deleted.\n"));
            return TRUE;
        }
        else {
            _tprintf(_T("Error opening key.\n"));
            return FALSE;
        }
    }

    lpEnd = lpSubKey + lstrlen(lpSubKey);

    if (*(lpEnd - 1) != TEXT('\\'))
    {
        *lpEnd = TEXT('\\');
        lpEnd++;
        *lpEnd = TEXT('\0');
    }

    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS)
    {
        do {

            *lpEnd = TEXT('\0');
            StringCchCat(lpSubKey, MAX_PATH * 2, szName);

            if (!regDelNodeRecurse(hKeyRoot, lpSubKey)) {
                break;
            }

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);


    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

BOOL deleteEventSource()
{
    TCHAR   szRegPath[MAX_PATH];

    _stprintf_s(szRegPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), PROVIDER_NAME );

    // Create the event source registry key
    return regDelNodeRecurse(HKEY_LOCAL_MACHINE, szRegPath);
}

void addEventSource()
{
    HKEY    hRegKey = NULL;
    DWORD   dwError = 0;
    TCHAR   szRegPath[MAX_PATH];
    TCHAR   szDLLPath[MAX_PATH];

    _stprintf_s(szRegPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s"), PROVIDER_NAME, PROVIDER_NAME);
    _stprintf_s(szDLLPath, _T("%s"), DLL_PATH);

    // Create the event source registry key
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szRegPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_READ | KEY_WRITE | KEY_SET_VALUE, NULL, &hRegKey, NULL) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: Couldn't create event source registry key: [%d].\n"), GetLastError());
        return;
    }
        // Name of the PE module that contains the message resource
    if (GetModuleFileName(NULL, szRegPath, MAX_PATH) == 0)
    {
        _tprintf(TEXT("ERROR: call to GetModuleFileName failed: [%d].\n"), GetLastError());
        return;
    }
    
    // Register EventMessageFile
    if (RegSetValueEx(hRegKey, _T("EventMessageFile"), 0, REG_EXPAND_SZ, (PBYTE)szDLLPath, (_tcslen(szDLLPath) + 1) * sizeof TCHAR) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to EventMessageFile failed: [%d].\n"), GetLastError());
        return;
    }
    
    // Register supported event types
    DWORD dwTypes = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    if (RegSetValueEx(hRegKey, _T("TypesSupported"), 0, REG_DWORD, (LPBYTE)&dwTypes, sizeof dwTypes) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to TypesSupported failed: [%d].\n"), GetLastError());
        return;
    }   
    _tprintf(TEXT("Finished configuring the Event Log.\n"));
   RegCloseKey(hRegKey);
   
}

BOOL processProtectedEvent(BOOL successfulInjection, TCHAR* processName, TCHAR* processID) {

    bool bSuccess = FALSE;
    DWORD eventType = EVENTLOG_AUDIT_SUCCESS;
    LPCTSTR aInsertions[2] = { NULL, NULL };

    if (!successfulInjection) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    // Open the eventlog
    HANDLE hEventLog = RegisterEventSource(NULL, PROVIDER_NAME);
    aInsertions[0] = processName;
    aInsertions[1] = processID;

    if (hEventLog){
       
        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            0,               
            PROCESS_PROTECTION_ADDED,           
            NULL,                       
            2,                          
            0,                          
            aInsertions,                
            NULL                        
        );
    }

    // Close eventlog
    DeregisterEventSource(hEventLog);
    return bSuccess;
}

BOOL processUnprotectedEvent(BOOL successfulIUnloading, TCHAR* processName, TCHAR* processID) {

    bool bSuccess = FALSE;
    DWORD eventType = EVENTLOG_AUDIT_SUCCESS;
    LPCTSTR aInsertions[2] = { NULL, NULL };

    if (!successfulIUnloading) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    // Open the eventlog
    HANDLE hEventLog = RegisterEventSource(NULL, PROVIDER_NAME);
    aInsertions[0] = processName;
    aInsertions[1] = processID;

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            0,               
            PROCESS_PROTECTION_REMOVED,           
            NULL,                       
            2,                          
            0,                          
            aInsertions,                
            NULL                        
        );
    }

    // Close eventlog
    DeregisterEventSource(hEventLog);
    return bSuccess;
}

std::basic_string<TCHAR> escapeIpv6Address(TCHAR* sourceAddress)
{
    std::basic_string<TCHAR> sourceAddressEscaped = sourceAddress;

    const std::basic_string<TCHAR> s = _T("\\:");
    const std::basic_string<TCHAR> t = _T(":");
    std::basic_string<TCHAR>::size_type n = 0;

    while ((n = sourceAddressEscaped.find(s, n)) != std::string::npos)
    {
        sourceAddressEscaped.replace(n, s.size(), t);
        n += t.size();
    }
    return sourceAddressEscaped;
}

BOOL rpcFunctionCalledEvent(BOOL callSuccessful, RpcEventParameters eventParams)
{
    bool bSuccess = FALSE;
    DWORD eventType = EVENTLOG_AUDIT_SUCCESS;
    LPCWSTR aInsertions[11] = {NULL};
   
    if (!callSuccessful) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    // Open the eventlog
    if (hEventLog == NULL)
    {
        hEventLog = RegisterEventSource(NULL, PROVIDER_NAME);
    }
      
    aInsertions[0] = (TCHAR*)eventParams.functionName.c_str();
    aInsertions[1] = (TCHAR*)eventParams.processID.c_str();
    aInsertions[2] = (TCHAR*)eventParams.processName.c_str();
    aInsertions[3] = (TCHAR*)eventParams.protocol.c_str();
    aInsertions[4] = (TCHAR*)eventParams.endpoint.c_str();
    aInsertions[5] = (TCHAR*)(escapeIpv6Address((TCHAR*)eventParams.sourceAddress.c_str())).c_str();
    aInsertions[6] = (TCHAR*)eventParams.uuidString.c_str();
    aInsertions[7] = (TCHAR*)eventParams.OpNum.c_str();
    aInsertions[8] = (TCHAR*)eventParams.clientName.c_str();
    aInsertions[9] = (TCHAR*)eventParams.authnLevel.c_str();
    aInsertions[10] = (TCHAR*)eventParams.authnSvc.c_str();

    if (hEventLog) {
        
        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            0,               
            RPC_SERVER_CALL,           
            NULL,                      
            11,                        
            0,                         
            aInsertions,               
            NULL                       
        );
    }
    else

    return bSuccess;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            // Close eventlog
            if (hEventLog != NULL) DeregisterEventSource(hEventLog);
            break;
    }
    return TRUE;
}

