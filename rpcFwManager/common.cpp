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

std::wstring StringToWString(const std::string& s)
{
	std::wstring temp(s.length(), L' ');
	std::copy(s.begin(), s.end(), temp.begin());
	return temp;
}

std::tuple<size_t, size_t, bool> getConfigOffsets(std::string confStr)
{
	size_t start_pos = confStr.find("!start!");
	size_t end_pos = confStr.find("!end!");

	if (start_pos == std::string::npos || end_pos == std::string::npos)
	{
		outputMessage(_T("Error reading start or end markers"));
		return std::make_tuple(0, 0, false);
	}
	start_pos += 7;

	return std::make_tuple(start_pos, end_pos, true);
}

void printMappedMeomryConfiguration()
{
	HANDLE hConfigurationMapFile = OpenFileMapping(FILE_MAP_READ, false, GLOBAL_SHARED_MEMORY);

	if (hConfigurationMapFile == nullptr)
	{
		outputMessage(L"\tNo RPC Firewall configuration loaded.");
		return;
	}

	char* mappedBuf = nullptr;
	mappedBuf = (char*)MapViewOfFile(hConfigurationMapFile, FILE_MAP_READ, 0, 0, MEM_BUF_SIZE);
	if (mappedBuf == nullptr)
	{
        outputMessage(TEXT("Error: Could not map view of configuration file."), GetLastError());
		CloseHandle(hConfigurationMapFile);
		return;
	}

	std::string privateConfigBuffer = mappedBuf;

	auto markers = getConfigOffsets(privateConfigBuffer);
	size_t start_pos = std::get<0>(markers);
	size_t end_pos = std::get<1>(markers);

	std::string configurationOnly = privateConfigBuffer.substr(start_pos, end_pos - start_pos);

	std::basic_istringstream<wchar_t> configStream(StringToWString(configurationOnly));
	std::wstring confLineString;
	wchar_t configLine[256];

	while (configStream.getline(configLine, 256))
	{
		confLineString = L"\t";
		confLineString += configLine;
		confLineString += _T(" ");

		if (_tcsstr(configLine, TEXT("fw:")))
		{
			outputMessage(confLineString.c_str());
		}
	}
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

		CloseHandle(hFile);
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

	return std::string("ver:" + std::to_string(verNumber) + " hash:" + std::to_string(hashValue) + "\r\n" + "!start!" + strToHash + "!end!");
}

void readConfigAndMapToMemory()
{
	outputMessage(L"About to read me some configurations...");
	CHAR* pBuf;
	DWORD bytesRead = 0;
	CHAR* confBuf = readConfigFile(&bytesRead);
	std::string confBufHashed;

	if (bytesRead > 0)
	{
		globalMappedMemory = mapNamedMemory();

		if (globalMappedMemory == nullptr)
		{
			outputMessage(L"No mapped memory! quitting...");
			std::quick_exit(-1);
		}

		pBuf = (CHAR*)MapViewOfFile(globalMappedMemory, FILE_MAP_ALL_ACCESS, 0, 0, MEM_BUF_SIZE);
		if (pBuf == nullptr)
		{
			outputMessage(L"Error calling MapViewOfFile", GetLastError());
			CloseHandle(globalMappedMemory);
			std::quick_exit(-1);
		}

		DWORD verNumber = getConfigVersionNumber(pBuf);
		confBufHashed = addHeaderToBuffer(verNumber + 1, confBuf, bytesRead);

		memset(pBuf, '\0', MEM_BUF_SIZE);
		const char* source = confBufHashed.c_str();
		try
		{
			errno_t err = memcpy_s(pBuf, MEM_BUF_SIZE, source, confBufHashed.length());
			if (err)
			{
				outputMessage(L"memcpy_s Error: failed to copy configuration to mapped memory.");
			}
		}
		catch (const std::exception& ex)
		{
			std::string what = ex.what();
			std::wstring Wwhat = StringToWString(what);
			outputMessage(Wwhat.c_str());
		}
		catch (...)
		{
			outputMessage(L"Unexpected exception!");
		}
		outputMessage(L"Configuration mapped to memory.");
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
