#pragma once
#ifdef LIBRARY_EXPORTS
#    define LIBRARY_API __declspec(dllexport)
#else
#    define LIBRARY_API __declspec(dllimport)
#endif

#include <string>

#define GLOBAL_RPCFW_CONFIG_UPDATE TEXT("Global\\RpcFwUpdateEvent")
#define GLOBAL_RPCFW_EVENT_UNPROTECT TEXT("Global\\RpcFwUninstalledEvent")
#define GLOBAL_RPCFW_MANAGER_DONE TEXT("Global\\RpcFwMgrDone")
#define GLOBAL_SHARED_MEMORY TEXT("Global\\RpcFwRules")
#define MEM_BUF_SIZE 0xFFFF

#define DllExport   __declspec( dllexport )

struct RpcEventParameters
{
	bool rpcAllowd;
	std::wstring functionName;
	std::wstring processID;
	std::wstring processName;
	std::wstring protocol;
	std::wstring endpoint;
	std::wstring sourceAddress;
	std::wstring uuidString;
	std::wstring OpNum;
	std::wstring clientName;
	std::wstring authnLevel;
	std::wstring authnSvc;
};

DllExport bool deleteEventSource();

DllExport void addEventSource();

DllExport bool processProtectedEvent(bool , wchar_t*, wchar_t* );

DllExport bool processUnprotectedEvent(bool, wchar_t*, wchar_t* );

DllExport bool rpcFunctionCalledEvent(bool , RpcEventParameters );

DllExport bool compareCharCaseInsensitive(wchar_t , wchar_t );

DllExport bool compareStringsCaseinsensitive(wchar_t*, wchar_t* );

DllExport bool compareStringsCaseinsensitive(wchar_t* , wchar_t* , size_t);
