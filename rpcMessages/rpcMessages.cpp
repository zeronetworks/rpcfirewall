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

HANDLE hEventLog = nullptr;

bool compareCharCaseInsensitive(wchar_t c1, wchar_t c2)
{
    if (c1 == c2)
        return true;
    else if (std::toupper(c1) == std::toupper(c2))
        return true;
    return false;
}

bool compareStringsCaseinsensitive(wchar_t* str1, wchar_t* str2)
{
    wchar_t tcharEnd = _T("\0")[0];

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

bool compareStringsCaseinsensitive(wchar_t* str1, wchar_t* str2, size_t maxLen)
{
    wchar_t tcharEnd = _T("\0")[0];

    for (size_t i = 0; i < maxLen; i++)
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

bool regDelNodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
{
    LPTSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    wchar_t szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS)
        return true;

    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            _tprintf(_T("Registry key already deleted.\n"));
            return true;
        }
        else {
            _tprintf(_T("Error opening key.\n"));
            return false;
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
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, nullptr,
        nullptr, nullptr, &ftWrite);

    if (lResult == ERROR_SUCCESS)
    {
        do {

            *lpEnd = TEXT('\0');
            StringCchCat(lpSubKey, MAX_PATH * 2, szName);

            if (!regDelNodeRecurse(hKeyRoot, lpSubKey)) {
                break;
            }

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, nullptr,
                nullptr, nullptr, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);


    lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    if (lResult == ERROR_SUCCESS)
        return true;

    return false;
}

bool deleteEventSource()
{
    wchar_t   szRegPath[MAX_PATH];

    _stprintf_s(szRegPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), PROVIDER_NAME );

    // Create the event source registry key
    return regDelNodeRecurse(HKEY_LOCAL_MACHINE, szRegPath);
}

void addEventSource()
{
    HKEY    hRegKey = nullptr;
    DWORD   dwError = 0;
    wchar_t   szRegPath[MAX_PATH];
    wchar_t   szDLLPath[MAX_PATH];

    _stprintf_s(szRegPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s"), PROVIDER_NAME, PROVIDER_NAME);
    _stprintf_s(szDLLPath, _T("%s"), DLL_PATH);

    // Create the event source registry key
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, szRegPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_READ | KEY_WRITE | KEY_SET_VALUE, nullptr, &hRegKey, nullptr) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: Couldn't create event source registry key: [%d].\n"), GetLastError());
        return;
    }
        // Name of the PE module that contains the message resource
    if (GetModuleFileName(nullptr, szRegPath, MAX_PATH) == 0)
    {
        _tprintf(TEXT("ERROR: call to GetModuleFileName failed: [%d].\n"), GetLastError());
        return;
    }
    
    // Register EventMessageFile
    if (RegSetValueEx(hRegKey, _T("EventMessageFile"), 0, REG_EXPAND_SZ, (PBYTE)szDLLPath, (DWORD)((_tcslen(szDLLPath) + 1) *  (DWORD)sizeof(wchar_t))) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to EventMessageFile failed: [%d].\n"), GetLastError());
        return;
    }
    
    // Register supported event types
    DWORD dwTypes = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    if (RegSetValueEx(hRegKey, _T("TypesSupported"), 0, REG_DWORD, (LPBYTE)&dwTypes, sizeof(dwTypes)) != ERROR_SUCCESS)
    {
        _tprintf(TEXT("ERROR: setting value to TypesSupported failed: [%d].\n"), GetLastError());
        return;
    }   
    _tprintf(TEXT("Finished configuring the Event Log.\n"));
   RegCloseKey(hRegKey);
   
}

bool processProtectedEvent(bool successfulInjection, wchar_t* processName, wchar_t* processID)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    LPCTSTR aInsertions[2] = { nullptr, nullptr };

    if (!successfulInjection) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    // Open the eventlog
    HANDLE hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    aInsertions[0] = processName;
    aInsertions[1] = processID;

    if (hEventLog){
       
        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            0,               
            PROCESS_PROTECTION_ADDED,           
            nullptr,                       
            2,                          
            0,                          
            aInsertions,                
            nullptr                        
        );
    }

    // Close eventlog
    DeregisterEventSource(hEventLog);
    return bSuccess;
}

bool processUnprotectedEvent(bool successfulIUnloading, wchar_t* processName, wchar_t* processID) {

    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    LPCTSTR aInsertions[2] = { nullptr, nullptr };

    if (!successfulIUnloading) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    // Open the eventlog
    HANDLE hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    aInsertions[0] = processName;
    aInsertions[1] = processID;

    if (hEventLog) {

        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            0,               
            PROCESS_PROTECTION_REMOVED,           
            nullptr,                       
            2,                          
            0,                          
            aInsertions,                
            nullptr                        
        );
    }

    // Close eventlog
    DeregisterEventSource(hEventLog);
    return bSuccess;
}

std::wstring escapeIpv6Address(wchar_t* sourceAddress)
{
    std::wstring sourceAddressEscaped = sourceAddress;

    const std::wstring s = _T("\\:");
    const std::wstring t = _T(":");
    std::wstring::size_type n = 0;

    while ((n = sourceAddressEscaped.find(s, n)) != std::string::npos)
    {
        sourceAddressEscaped.replace(n, s.size(), t);
        n += t.size();
    }
    return sourceAddressEscaped;
}

bool rpcFunctionCalledEvent(bool callSuccessful, RpcEventParameters eventParams)
{
    bool bSuccess = false;
    WORD eventType = EVENTLOG_AUDIT_SUCCESS;
    LPCWSTR aInsertions[11] = {nullptr};
   
    if (!callSuccessful) {
        eventType = EVENTLOG_AUDIT_FAILURE;
    }

    // Open the eventlog
    if (hEventLog == nullptr)
    {
        hEventLog = RegisterEventSource(nullptr, PROVIDER_NAME);
    }
      
    aInsertions[0] = (wchar_t*)eventParams.functionName.c_str();
    aInsertions[1] = (wchar_t*)eventParams.processID.c_str();
    aInsertions[2] = (wchar_t*)eventParams.processName.c_str();
    aInsertions[3] = (wchar_t*)eventParams.protocol.c_str();
    aInsertions[4] = (wchar_t*)eventParams.endpoint.c_str();
    aInsertions[5] = (wchar_t*)(escapeIpv6Address((wchar_t*)eventParams.sourceAddress.c_str())).c_str();
    aInsertions[6] = (wchar_t*)eventParams.uuidString.c_str();
    aInsertions[7] = (wchar_t*)eventParams.OpNum.c_str();
    aInsertions[8] = (wchar_t*)eventParams.clientName.c_str();
    aInsertions[9] = (wchar_t*)eventParams.authnLevel.c_str();
    aInsertions[10] = (wchar_t*)eventParams.authnSvc.c_str();

    if (hEventLog) {
        
        bSuccess = ReportEvent(
            hEventLog,                  
            eventType,  
            0,               
            RPC_SERVER_CALL,           
            nullptr,                      
            11,                        
            0,                         
            aInsertions,               
            nullptr                       
        );
    }

    return bSuccess;
}


bool APIENTRY DllMain( HMODULE hModule,
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
            if (hEventLog != nullptr) DeregisterEventSource(hEventLog);
            break;
    }
    return true;
}

