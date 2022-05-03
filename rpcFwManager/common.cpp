#include "stdafx.h"
#include "common.h"

bool interactive;
HANDLE globalMappedMemory = nullptr;
HANDLE globalUnprotectEvent = nullptr;

CHAR configBuf[MEM_BUF_SIZE];

HANDLE mapNamedMemory()
{
	HANDLE hMapFile = nullptr;
	SECURITY_ATTRIBUTES sa = { 0 };
	PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

	if (createSecurityAttributes(&sa, psd))
	{
		hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, MEM_BUF_SIZE, GLOBAL_SHARED_MEMORY);
		if (hMapFile == nullptr)
		{
			outputMessage(TEXT("Error calling CreateFileMapping %d.\n"), GetLastError());
		}
	}

	LocalFree(psd);

	return hMapFile;
}

std::wstring getProcessBinaryPath()
{
	std::wstring binPath;
	HANDLE hProcess = GetCurrentProcess();
	if (!hProcess) return binPath;

	wchar_t szBuffer[MAX_PATH];
	ZeroMemory(szBuffer, sizeof(szBuffer));
	DWORD dwSize = sizeof(szBuffer) / sizeof(szBuffer[0]) - 1;
	QueryFullProcessImageName(hProcess, 0, szBuffer, &dwSize);

	binPath = szBuffer;

	return binPath;
}

CHAR* readConfigFile(DWORD* bufLen)
{
	std::wstring cfgFwPath = getProcessBinaryPath();

	if (!cfgFwPath.empty())
	{
		size_t offset = cfgFwPath.rfind(L"\\", cfgFwPath.length());
		cfgFwPath = cfgFwPath.substr(0, offset);
		cfgFwPath = cfgFwPath + L"\\" + CONF_FILE_NAME;

		outputMessage(cfgFwPath.c_str());

		//std::wstring cfgFwPath = getFullPathOfFile(std::wstring(CONF_FILE_NAME));
		HANDLE hFile = CreateFile(cfgFwPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			outputMessage(TEXT("No configuration file found %d.\n"), GetLastError());
		}
		else if (!ReadFile(hFile, configBuf, MEM_BUF_SIZE - 1, bufLen, nullptr))
		{
			outputMessage(TEXT("ERROR: ReadFile %d.\n"), GetLastError());

		}
	}

	return configBuf;
}

std::string extractKeyValueFromConfig(std::string confLine, std::string key)
{
	confLine += (" ");
	size_t keyOffset = confLine.find(key);

	if (keyOffset == std::string::npos) return "\0";

	size_t nextKeyOffset = confLine.find(" ", keyOffset + 1);

	if (nextKeyOffset == std::string::npos) return "\0";

	return confLine.substr(keyOffset + key.size(), nextKeyOffset - keyOffset - key.size());
}

DWORD getConfigVersionNumber(CHAR* buff)
{
	std::string buffString(buff);
	std::string version = extractKeyValueFromConfig(buffString, "ver:");

	if (version.empty())
	{
		return 0;
	}

	return std::stoi(version);
}

std::string addHeaderToBuffer(DWORD verNumber, CHAR* confBuf, DWORD bufSize)
{
	std::string strToHash = confBuf;
	strToHash.resize(bufSize);
	size_t hashValue = std::hash<std::string>{}(strToHash);

	std::string resultBuf = "ver:" + std::to_string(verNumber) + " hash:" + std::to_string(hashValue) + "\r\n" + "!start!" + strToHash + "!end!";

	return resultBuf;
}

void readConfigAndMapToMemory()
{
	CHAR* pBuf;
	DWORD bytesRead = 0;
	CHAR* confBuf = readConfigFile(&bytesRead);

	if (bytesRead > 0)
	{
		globalMappedMemory = mapNamedMemory();

		if (globalMappedMemory == nullptr)
		{
			std::quick_exit(-1);
		}

		pBuf = (CHAR*)MapViewOfFile(globalMappedMemory, FILE_MAP_ALL_ACCESS, 0, 0, MEM_BUF_SIZE);
		if (pBuf == nullptr)
		{
			_tprintf(TEXT("Error calling MapViewOfFile %d.\n"), GetLastError());
			CloseHandle(globalMappedMemory);
			std::quick_exit(-1);
		}

		DWORD verNumber = getConfigVersionNumber(pBuf);
		std::string confBufHashed = addHeaderToBuffer(verNumber + 1, confBuf, bytesRead);

		memset(pBuf, '\0', MEM_BUF_SIZE);
		CopyMemory((PVOID)pBuf, confBufHashed.c_str(), bytesRead + confBufHashed.length());
	}
}

bool createSecurityAttributes(SECURITY_ATTRIBUTES* psa, PSECURITY_DESCRIPTOR psd)
{
	if (InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) != 0)
	{
		if (SetSecurityDescriptorDacl(psd, true, nullptr, false) != 0)
		{
			(*psa).nLength = sizeof(*psa);
			(*psa).lpSecurityDescriptor = psd;
			(*psa).bInheritHandle = false;

			return true;
		}
		else
		{
			outputMessage(TEXT("SetSecurityDescriptorDacl failed : %d.\n"), GetLastError());
		}
	}
	else
	{
		outputMessage(TEXT("InitializeSecurityDescriptor failed : %d.\n"), GetLastError());
	}

	return false;
}

HANDLE createGlobalEvent(bool manualReset, bool initialState, wchar_t* eventName)
{
	HANDLE gEvent = nullptr;
	SECURITY_ATTRIBUTES sa = { 0 };
	PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

	//TODO: return value instead of passing as ref
	if (createSecurityAttributes(&sa, psd))
	{
		gEvent = CreateEvent(&sa, manualReset, initialState, eventName);
		if (gEvent != nullptr)
		{
			if (ResetEvent(gEvent) == 0)
			{
				std::wstring msg = L"Error: ResetEvent for";
				msg += eventName;
				msg += +L" failed with";
				outputMessage(msg.c_str(), GetLastError());
			}
		}
		else
		{
			std::wstring msg = L"Error: could not create or get a global event ";
			msg += eventName;
			outputMessage(msg.c_str(), GetLastError());
		}
	}

	LocalFree(psd);

	return gEvent;
}

void createAllGloblEvents()
{
	globalUnprotectEvent = createGlobalEvent(true, false, (wchar_t*)GLOBAL_RPCFW_EVENT_UNPROTECT);
}

void writeDebugMessage(const wchar_t* msg)
{
	std::wstring dbgMsg = SERVICE_NAME;
	dbgMsg += L" : ";
	dbgMsg += msg;

	OutputDebugString(dbgMsg.c_str());
}

void outputMessage(const wchar_t* msg)
{
	std::wstring msgStr = msg;
	msgStr += L"\n";

	if (interactive) _tprintf(msgStr.c_str());
	else writeDebugMessage(msgStr.c_str());
}

void outputMessage(const wchar_t* msg, DWORD errnum)
{
	std::wstring msgStr = msg;
	msgStr += L" : ";
	msgStr += std::to_wstring(errnum);
	
	outputMessage(msgStr.c_str());
}

std::wstring getFullPathOfFile(const std::wstring& filename)
{
	wchar_t  filePath[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	if (!GetCurrentDirectory(bufCharCount, filePath))
	{
		outputMessage(TEXT("ERROR: Couldn't get the current directory"), GetLastError());
		return std::wstring();
	}

	return std::wstring(filePath) + _T("\\") + filename;
}
