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
	BOOL rpcAllowd;
	std::basic_string<TCHAR> functionName;
	std::basic_string<TCHAR> processID;
	std::basic_string<TCHAR> processName;
	std::basic_string<TCHAR> protocol;
	std::basic_string<TCHAR> endpoint;
	std::basic_string<TCHAR> sourceAddress;
	std::basic_string<TCHAR> uuidString;
	std::basic_string<TCHAR> OpNum;
	std::basic_string<TCHAR> clientName;
	std::basic_string<TCHAR> authnLevel;
	std::basic_string<TCHAR> authnSvc;
};

DllExport BOOL deleteEventSource();

DllExport void addEventSource();

DllExport BOOL processProtectedEvent(BOOL , TCHAR*, TCHAR* );

DllExport BOOL processUnprotectedEvent(BOOL, TCHAR*, TCHAR* );

DllExport BOOL rpcFunctionCalledEvent(BOOL , RpcEventParameters );

DllExport BOOL compareCharCaseInsensitive(TCHAR , TCHAR );

DllExport BOOL compareStringsCaseinsensitive(TCHAR*, TCHAR* );

DllExport BOOL compareStringsCaseinsensitive(TCHAR* , TCHAR* , size_t);
