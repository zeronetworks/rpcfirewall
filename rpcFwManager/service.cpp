#include "stdafx.h"
#include "common.h"
#include "EventSink.h"
#include "Injections.h"

SERVICE_STATUS globalServiceStatus = { 0 };
SERVICE_STATUS_HANDLE globalServcieStatusHandle = nullptr;
HANDLE globalServiceStopEvent = INVALID_HANDLE_VALUE;
bool alreadyStarted = false;

struct serviceHandleWrapper
{
	serviceHandleWrapper() {}

	serviceHandleWrapper(serviceHandleWrapper&& other) :
		h(other.h)
	{
		other.h = nullptr;
	}

	~serviceHandleWrapper()
	{
		if (h != nullptr)
		{
			CloseServiceHandle(h);
		}
	}

	SC_HANDLE h = nullptr;
};

serviceHandleWrapper getSCManagerHandle()
{
	serviceHandleWrapper schSCManager;
	// Get a handle to the SCM database. 
	schSCManager.h = OpenSCManager(
		nullptr,                    // local computer
		nullptr,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (nullptr == schSCManager.h)
	{
		outputMessage(L"OpenSCManager failed", GetLastError());
	}

	return schSCManager;
}

serviceHandleWrapper getServiceHandle(serviceHandleWrapper schSCManager, const wchar_t* serviceName)
{
	serviceHandleWrapper schService;

	schService.h = OpenService(
		schSCManager.h,         
		serviceName,            
		SERVICE_ALL_ACCESS);

	/*if (schService.h == nullptr)
	{
		outputMessage(L"OpenService failed", GetLastError());
	}*/
	
	return schService;
}

bool isServiceInstalled()
{
	serviceHandleWrapper serviceManagerWrapper = getSCManagerHandle();
	serviceHandleWrapper schService = getServiceHandle(std::move(serviceManagerWrapper), SERVICE_NAME);

	return schService.h == nullptr ? false : true;
}

void serviceStop()
{
	serviceHandleWrapper serviceManagerWrapper = getSCManagerHandle();
	serviceHandleWrapper schService = getServiceHandle(std::move(serviceManagerWrapper), SERVICE_NAME);

	if (schService.h != nullptr)
	{
		SERVICE_STATUS_PROCESS ssp;
		DWORD dwBytesNeeded;
		DWORD dwWaitTime;
		DWORD dwTimeout = 30000;
		DWORD dwStartTime = GetTickCount();

		if (!QueryServiceStatusEx(
			schService.h,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&ssp,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytesNeeded))
		{
			outputMessage(L"QueryServiceStatusEx failed", GetLastError());
			return;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
		{
			outputMessage(L"Service is already stopped.");
			return;
		}

		// If a stop is pending, wait for it.

		while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
		{
			outputMessage(L"Service stop pending...\n");

			// Do not wait longer than the wait hint. A good interval is 
			// one-tenth of the wait hint but not less than 1 second  
			// and not more than 10 seconds. 

			dwWaitTime = ssp.dwWaitHint / 10;

			if (dwWaitTime < 1000)
				dwWaitTime = 1000;
			else if (dwWaitTime > 10000)
				dwWaitTime = 10000;

			Sleep(dwWaitTime);

			if (!QueryServiceStatusEx(
				schService.h,
				SC_STATUS_PROCESS_INFO,
				(LPBYTE)&ssp,
				sizeof(SERVICE_STATUS_PROCESS),
				&dwBytesNeeded))
			{
				outputMessage(L"QueryServiceStatusEx failed.", GetLastError());
				return;
			}

			if (ssp.dwCurrentState == SERVICE_STOPPED)
			{
				outputMessage(L"Service stopped successfully.");
				return;
			}

			if (GetTickCount() - dwStartTime > dwTimeout)
			{
				outputMessage(L"Service stop timed out.");
				return;
			}
		}

		// Send a stop code to the service.

		if (!ControlService(
			schService.h,
			SERVICE_CONTROL_STOP,
			(LPSERVICE_STATUS)&ssp))
		{
			outputMessage(L"ControlService failed", GetLastError());
			return;
		}

		// Wait for the service to stop.

		while (ssp.dwCurrentState != SERVICE_STOPPED)
		{
			Sleep(ssp.dwWaitHint);
			if (!QueryServiceStatusEx(
				schService.h,
				SC_STATUS_PROCESS_INFO,
				(LPBYTE)&ssp,
				sizeof(SERVICE_STATUS_PROCESS),
				&dwBytesNeeded))
			{
				outputMessage(L"QueryServiceStatusEx failed", GetLastError());
				return;
			}

			if (ssp.dwCurrentState == SERVICE_STOPPED)
				break;

			if (GetTickCount() - dwStartTime > dwTimeout)
			{
				outputMessage(L"Wait timed out");
				return;
			}
		}
		outputMessage(L"Service stopped successfully.");
	}
}

void serviceStart()
{
	serviceHandleWrapper serviceManagerWrapper = getSCManagerHandle();
	serviceHandleWrapper schService = getServiceHandle(std::move(serviceManagerWrapper), SERVICE_NAME);

	if (schService.h != nullptr)
	{
		SERVICE_STATUS_PROCESS ssStatus;
		DWORD dwOldCheckPoint;
		DWORD dwStartTickCount;
		DWORD dwWaitTime;
		DWORD dwBytesNeeded;

		if (!QueryServiceStatusEx(
			schService.h,                  // handle to service 
			SC_STATUS_PROCESS_INFO,        // information level
			(LPBYTE)&ssStatus,             // address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))              // size needed if buffer is too small
		{
			outputMessage(L"QueryServiceStatusEx failed", GetLastError());
			return;
		}

		// Check if the service is already running. It would be possible 
		// to stop the service here, but for simplicity this example just returns. 

		if (ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
		{
			outputMessage(L"Cannot start the service because it is already running");
			return;
		}

		// Save the tick count and initial checkpoint.

		dwStartTickCount = GetTickCount();
		dwOldCheckPoint = ssStatus.dwCheckPoint;

		// Wait for the service to stop before attempting to start it.

		while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
		{
			// Do not wait longer than the wait hint. A good interval is 
			// one-tenth of the wait hint but not less than 1 second  
			// and not more than 10 seconds. 

			dwWaitTime = ssStatus.dwWaitHint / 10;

			if (dwWaitTime < 1000)
				dwWaitTime = 1000;
			else if (dwWaitTime > 10000)
				dwWaitTime = 10000;

			Sleep(dwWaitTime);

			// Check the status until the service is no longer stop pending. 

			if (!QueryServiceStatusEx(
				schService.h,                     // handle to service 
				SC_STATUS_PROCESS_INFO,         // information level
				(LPBYTE)&ssStatus,             // address of structure
				sizeof(SERVICE_STATUS_PROCESS), // size of structure
				&dwBytesNeeded))              // size needed if buffer is too small
			{
				outputMessage(L"QueryServiceStatusEx failed", GetLastError());
				return;
			}

			if (ssStatus.dwCheckPoint > dwOldCheckPoint)
			{
				// Continue to wait and check.

				dwStartTickCount = GetTickCount();
				dwOldCheckPoint = ssStatus.dwCheckPoint;
			}
			else
			{
				if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
				{
					outputMessage(L"Timeout waiting for service to stop");
					return;
				}
			}
		}

		// Attempt to start the service.

		if (!StartService(
			schService.h,  // handle to service 
			0,           // number of arguments 
			NULL))      // no arguments 
		{
			outputMessage(L"StartService failed", GetLastError());
			return;
		}
		else printf("Service start pending...\n");

		// Check the status until the service is no longer start pending. 

		if (!QueryServiceStatusEx(
			schService.h,                     // handle to service 
			SC_STATUS_PROCESS_INFO,         // info level
			(LPBYTE)&ssStatus,             // address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))              // if buffer too small
		{
			outputMessage(L"QueryServiceStatusEx failed", GetLastError());
			return;
		}

		// Save the tick count and initial checkpoint.

		dwStartTickCount = GetTickCount();
		dwOldCheckPoint = ssStatus.dwCheckPoint;

		while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
		{
			// Do not wait longer than the wait hint. A good interval is 
			// one-tenth the wait hint, but no less than 1 second and no 
			// more than 10 seconds. 

			dwWaitTime = ssStatus.dwWaitHint / 10;

			if (dwWaitTime < 1000)
				dwWaitTime = 1000;
			else if (dwWaitTime > 10000)
				dwWaitTime = 10000;

			Sleep(dwWaitTime);

			// Check the status again. 

			if (!QueryServiceStatusEx(
				schService.h,             // handle to service 
				SC_STATUS_PROCESS_INFO, // info level
				(LPBYTE)&ssStatus,             // address of structure
				sizeof(SERVICE_STATUS_PROCESS), // size of structure
				&dwBytesNeeded))              // if buffer too small
			{
				outputMessage(L"QueryServiceStatusEx failed", GetLastError());
				break;
			}

			if (ssStatus.dwCheckPoint > dwOldCheckPoint)
			{
				// Continue to wait and check.

				dwStartTickCount = GetTickCount();
				dwOldCheckPoint = ssStatus.dwCheckPoint;
			}
			else
			{
				if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
				{
					// No progress made within the wait hint.
					break;
				}
			}
		}

		// Determine whether the service is running.

		if (ssStatus.dwCurrentState == SERVICE_RUNNING)
		{
			outputMessage(L"Service started successfully.\n");
		}
		else
		{
			outputMessage(L"Service not started. \n");
			outputMessage(L"  Current State", ssStatus.dwCurrentState);
			outputMessage(L"  Exit Code", ssStatus.dwWin32ExitCode);
			outputMessage(L"  Check Point", ssStatus.dwCheckPoint);
			outputMessage(L"  Wait Hint", ssStatus.dwWaitHint);
		}
	}
}

void serviceInstall(DWORD startType)
{
	serviceHandleWrapper serviceManagerWrapper = getSCManagerHandle();
		
	TCHAR szPath[MAX_PATH];

	if (!GetModuleFileName(nullptr, szPath, MAX_PATH))
	{
		outputMessage(L"GetModuleFileName failed",GetLastError());
		return;
	}

	serviceHandleWrapper schService;

	schService.h = CreateService(
		serviceManagerWrapper.h,        // SCM database 
		SERVICE_NAME,                   // name of service 
		SERVICE_NAME,                   // service name to display 
		SERVICE_ALL_ACCESS,        // desired access 
		SERVICE_WIN32_OWN_PROCESS, // service type 
		SERVICE_DEMAND_START,      // start type 
		SERVICE_ERROR_NORMAL,      // error control type 
		szPath,                    // path to service's binary 
		NULL,                      // no load ordering group 
		NULL,                      // no tag identifier 
		NULL,                      // no dependencies 
		NULL,                      // LocalSystem account 
		NULL);                     // no password 

	if (schService.h == nullptr)
	{
		outputMessage(L"CreateService failed", GetLastError());
		return;
	}
	else outputMessage(L"Service installed successfully");
}

void serviceUninstall()
{
	serviceHandleWrapper serviceManagerWrapper = getSCManagerHandle();
	serviceHandleWrapper schService = getServiceHandle(std::move(serviceManagerWrapper), SERVICE_NAME);
	
	if (schService.h == nullptr)
	{
		outputMessage(L"DeleteService failed - could not get handle to service");
		return;
	}

	if (!DeleteService(schService.h))
	{
		outputMessage(L"DeleteService failed", GetLastError());
		return;
	}
	
	outputMessage(L"Service deleted successfully");
}

void serviceUpdateStartType(DWORD startType)
{
	serviceHandleWrapper serviceManagerWrapper = getSCManagerHandle();
	serviceHandleWrapper schService = getServiceHandle(std::move(serviceManagerWrapper), SERVICE_NAME);

	if (!ChangeServiceConfig(schService.h, SERVICE_WIN32_OWN_PROCESS,startType, SERVICE_ERROR_NORMAL, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
	{
		outputMessage(L"Updating service start opetion failed", GetLastError());
		return;
	}
	else outputMessage(L"Service configured to start automatically.");
}

void serviceMakeAutostart()
{
	serviceUpdateStartType(SERVICE_AUTO_START);
}

void WINAPI serviceCtrlHandler(DWORD CtrlCode)
{
	switch (CtrlCode)
	{
	case SERVICE_CONTROL_STOP:
		
		outputMessage(L"Service stopping...");

		if (globalServiceStatus.dwCurrentState != SERVICE_RUNNING)
			break;

		globalServiceStatus.dwControlsAccepted = 0;
		globalServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		globalServiceStatus.dwWin32ExitCode = 0;
		globalServiceStatus.dwCheckPoint = 4;

		if (SetServiceStatus(globalServcieStatusHandle, &globalServiceStatus) == false)
		{
			writeDebugMessage(L"ServiceCtrlHandler: SetServiceStatus returned error");
		}

		// This will signal the worker thread to start shutting down
		SetEvent(globalServiceStopEvent);

		break;

	default:
		break;
	}
}

DWORD WINAPI serviceWorkerThread(LPVOID lpParam)
{
	wmiEventRegistrant wmiProcessRegistrant;
	wmiProcessRegistrant.registerForProcessCreatedEvents();
	
	WaitForSingleObject(globalServiceStopEvent, INFINITE);

	outputMessage(L"Service worker stopping...");

	return ERROR_SUCCESS;
}

void WINAPI serviceMain(DWORD argc, LPTSTR* argv)
{
	outputMessage(_T("Service Starting..."));
	DWORD Status = E_FAIL;

	// Register our service control handler with the SCM
	globalServcieStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, serviceCtrlHandler);

	if (globalServcieStatusHandle == nullptr)
	{
		return;
	}

	// Tell the service controller we are starting
	ZeroMemory(&globalServiceStatus, sizeof(globalServiceStatus));
	globalServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	globalServiceStatus.dwControlsAccepted = 0;
	globalServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	globalServiceStatus.dwWin32ExitCode = 0;
	globalServiceStatus.dwServiceSpecificExitCode = 0;
	globalServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(globalServcieStatusHandle, &globalServiceStatus) == false)
	{
		outputMessage(_T("ServiceMain: SetServiceStatus returned error"));
	}

	 // Create a service stop event to wait on later
	globalServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (globalServiceStopEvent == nullptr)
	{
		// Error creating event
		// Tell service controller we are stopped and exit
		globalServiceStatus.dwControlsAccepted = 0;
		globalServiceStatus.dwCurrentState = SERVICE_STOPPED;
		globalServiceStatus.dwWin32ExitCode = GetLastError();
		globalServiceStatus.dwCheckPoint = 1;

		if (SetServiceStatus(globalServcieStatusHandle, &globalServiceStatus) == false)
		{
			outputMessage(_T("ServiceMain: SetServiceStatus returned error"));
		}
		return;
	}

	// Tell the service controller we are started
	globalServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	globalServiceStatus.dwCurrentState = SERVICE_RUNNING;
	globalServiceStatus.dwWin32ExitCode = 0;
	globalServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(globalServcieStatusHandle, &globalServiceStatus) == false)
	{
		outputMessage(_T("ServiceMain: SetServiceStatus returned error"));
	}

	createAllGloblEvents();
	readConfigAndMapToMemory();
	
	crawlProcesses(0);

	// Start a thread that will perform the main task of the service
	HANDLE hThread = CreateThread(NULL, 0, serviceWorkerThread, NULL, 0, NULL);

	// Wait until our worker thread exits signaling that the service needs to stop
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(globalServiceStopEvent);

	// Tell the service controller we are stopped
	globalServiceStatus.dwControlsAccepted = 0;
	globalServiceStatus.dwCurrentState = SERVICE_STOPPED;
	globalServiceStatus.dwWin32ExitCode = 0;
	globalServiceStatus.dwCheckPoint = 3;

	if (SetServiceStatus(globalServcieStatusHandle, &globalServiceStatus) == false)
	{
		outputMessage(_T("SetServiceStatus returned error"));
	}
}

bool setupService()
{
	SERVICE_TABLE_ENTRY ServiceTable[] =
	{
		{(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)serviceMain},
		{NULL, NULL}
	};

	if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
	{
		writeDebugMessage(_T("Error starting service"));
		return false;
	}
	return true;
}