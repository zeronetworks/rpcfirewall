#include "stdafx.h"

#include <detours.h>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <strsafe.h>


static long (WINAPI* realNdrStubCall2)(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase) = NdrStubCall2;
long WINAPI myNdrStubCall2(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase);

static long (WINAPI* realNdrStubCall3)(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase) = NdrStubCall3;
long WINAPI myNdrStubCall3(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase);

static void (WINAPI* realNdrServerCallAll)(PRPC_MESSAGE pRpcMsg) = NdrServerCallAll;
void WINAPI myNdrServerCallAll(PRPC_MESSAGE pRpcMsg);

static void (WINAPI* realNdrAsyncServerCall)(PRPC_MESSAGE pRpcMsg) = NdrAsyncServerCall;
void WINAPI myNdrAsyncServerCall(PRPC_MESSAGE pRpcMsg);

static void (WINAPI* realNdr64AsyncServerCallAll)(PRPC_MESSAGE pRpcMsg) = Ndr64AsyncServerCallAll;
void WINAPI myNdr64AsyncServerCallAll(PRPC_MESSAGE pRpcMsg);

static void (WINAPI* realNdr64AsyncServerCall64)(PRPC_MESSAGE pRpcMsg) = Ndr64AsyncServerCall64;
void WINAPI myNdr64AsyncServerCall64(PRPC_MESSAGE pRpcMsg);

static void (WINAPI* realNdrServerCallNdr64)(PRPC_MESSAGE pRpcMsg) = NdrServerCallNdr64;
void WINAPI myNdrServerCallNdr64(PRPC_MESSAGE pRpcMsg);

std::wofstream outfile;

DWORD gFreqOffset = 0;

std::ostream& hex_dump(std::ostream& os, const void* buffer,
	std::size_t bufsize, bool showPrintableChars = true)
{
	if (buffer == nullptr) {
		return os;
	}
	auto oldFormat = os.flags();
	auto oldFillChar = os.fill();
	constexpr std::size_t maxline{ 8 };
	// create a place to store text version of string
	char renderString[maxline + 1];
	char* rsptr{ renderString };
	// convenience cast
	const unsigned char* buf{ reinterpret_cast<const unsigned char*>(buffer) };

	for (std::size_t linecount = maxline; bufsize; --bufsize, ++buf) {
		os << std::setw(2) << std::setfill('0') << std::hex
			<< static_cast<unsigned>(*buf) << ' ';
		*rsptr++ = std::isprint(*buf) ? *buf : '.';
		if (--linecount == 0) {
			*rsptr++ = '\0';  // terminate string
			if (showPrintableChars) {
				os << " | " << renderString;
			}
			os << '\n';
			rsptr = renderString;
			linecount = min(maxline, bufsize);
		}
	}
	// emit newline if we haven't already
	if (rsptr != renderString) {
		if (showPrintableChars) {
			for (*rsptr++ = '\0'; rsptr != &renderString[maxline + 1]; ++rsptr) {
				os << "   ";
			}
			os << " | " << renderString;
		}
		os << '\n';
	}
}

struct hexDump {
	const void* buffer;
	std::size_t bufsize;
	hexDump(const void* buf, std::size_t bufsz) : buffer{ buf }, bufsize{ bufsz } {}
	friend std::ostream& operator<<(std::ostream& out, const hexDump& hd) {
		return hex_dump(out, hd.buffer, hd.bufsize, true);
	}
};

constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7','8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

std::wstring hexStr(unsigned char* data, int len)
{
	std::wstring s(len * 2, ' ');
	for (int i = 0; i < len; ++i) {
		s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}

long WINAPI myNdrStubCall2(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase)
{
	RPC_BINDING_HANDLE serverBinding;
	wchar_t* szStringBinding;
	std::wstring szWstringBinding;
	UUID serverObjectUuid;
	RPC_CSTR szStringUuid;
	UUID* uuidPointer;
	byte* byteUuidPointer;
	unsigned char uuidData[20];
	std::wostringstream rpcEventLine;

	try {

		RPC_STATUS status = RpcBindingServerFromClient(0, &serverBinding);
		if (status == RPC_S_OK) {
			status = RpcBindingToStringBinding(serverBinding, (RPC_WSTR*)&szStringBinding);
			if (status == RPC_S_OK) {
				if (wcsstr(szStringBinding, L"ncacn_ip_tcp") || wcsstr(szStringBinding, L"ncacn_nb_tcp") || wcsstr(szStringBinding, L"ncacn_np")) {
					rpcEventLine << "NdrStubCall2,";
					szWstringBinding = std::wstring(szStringBinding);
					//wcsncpy_s(wcsstr(szStringBinding, L":"), 1,L",", 1);
					size_t pos = szWstringBinding.find(L":", 0);
					if (pos != std::string::npos) {
						szWstringBinding.replace(pos, 1, L",");
					}
					rpcEventLine << szWstringBinding << L",";

					status = RpcBindingInqObject(serverBinding, &serverObjectUuid);
					if (status == RPC_S_OK) {
						byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

						memcpy(&uuidData, byteUuidPointer + 8, 20);
						rpcEventLine << hexStr(&uuidData[15], 1) << hexStr(&uuidData[14], 1) << hexStr(&uuidData[13], 1) << hexStr(&uuidData[12], 1) << "-" << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << "-" << hexStr(&uuidData[4], 2) << "-" << hexStr(&uuidData[6], 6);
						//outfile << "UUID: " << hexStr(&uuidData[15], 1) << hexStr(&uuidData[14], 1) << hexStr(&uuidData[13], 1) << hexStr(&uuidData[12], 1) << "-" << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << "-" << hexStr(&uuidData[4], 2) << "-" << hexStr(&uuidData[6], 6) << std::endl;
						rpcEventLine << "," << std::to_wstring(pRpcMsg->ProcNum);
						outfile << rpcEventLine.str() << std::endl;
					}
					else
					{
						outfile << "RpcBindingInqObject failed....: " << std::endl;
					}
				}
			}
			else {
				outfile << "Not good:(\n" << std::endl;
			}
		}
	}
	catch (const std::runtime_error& re) {
		outfile << "ERORR: runtime " << re.what() << std::endl;
	}
	catch (const std::exception& ex) {
		outfile << "ERORR: exception " << ex.what() << std::endl;
	}
	catch (...) {
		outfile << "ERORR: Unknown failure occurred. Possible memory corruption " << std::endl;
	}

	return realNdrStubCall2(pThis, pChannel, pRpcMsg, pdwStubPhase);
}

long WINAPI myNdrStubCall3(void* pThis, void* pChannel, PRPC_MESSAGE pRpcMsg, unsigned long* pdwStubPhase)
{
	RPC_BINDING_HANDLE serverBinding;
	wchar_t* szStringBinding;
	std::wstring szWstringBinding;
	UUID serverObjectUuid;
	RPC_CSTR szStringUuid;
	UUID* uuidPointer;
	byte* byteUuidPointer;
	unsigned char uuidData[20];
	std::wostringstream rpcEventLine;

	try {

		RPC_STATUS status = RpcBindingServerFromClient(0, &serverBinding);
		if (status == RPC_S_OK) {
			status = RpcBindingToStringBinding(serverBinding, (RPC_WSTR*)&szStringBinding);
			if (status == RPC_S_OK) {
				if (wcsstr(szStringBinding, L"ncacn_ip_tcp") || wcsstr(szStringBinding, L"ncacn_nb_tcp") || wcsstr(szStringBinding, L"ncacn_np")) {
					rpcEventLine << "myNdrStubCall3,";
					szWstringBinding = std::wstring(szStringBinding);
					//wcsncpy_s(wcsstr(szStringBinding, L":"), 1,L",", 1);
					size_t pos = szWstringBinding.find(L":", 0);
					if (pos != std::string::npos) {
						szWstringBinding.replace(pos, 1, L",");
					}
					rpcEventLine << szWstringBinding << L",";

					status = RpcBindingInqObject(serverBinding, &serverObjectUuid);
					if (status == RPC_S_OK) {
						byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

						memcpy(&uuidData, byteUuidPointer + 8, 20);
						rpcEventLine << hexStr(&uuidData[15], 1) << hexStr(&uuidData[14], 1) << hexStr(&uuidData[13], 1) << hexStr(&uuidData[12], 1) << "-" << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << "-" << hexStr(&uuidData[4], 2) << "-" << hexStr(&uuidData[6], 6);
						//outfile << "UUID: " << hexStr(&uuidData[15], 1) << hexStr(&uuidData[14], 1) << hexStr(&uuidData[13], 1) << hexStr(&uuidData[12], 1) << "-" << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << "-" << hexStr(&uuidData[4], 2) << "-" << hexStr(&uuidData[6], 6) << std::endl;
						rpcEventLine << "," << std::to_wstring(pRpcMsg->ProcNum);
						outfile << rpcEventLine.str() << std::endl;
					}
					else
					{
						outfile << "RpcBindingInqObject failed....: " << std::endl;
					}
				}
			}
			else {
				outfile << "Not good:(\n" << std::endl;
			}
		}
	}
	catch (const std::runtime_error& re) {
		outfile << "ERORR: runtime " << re.what() << std::endl;
	}
	catch (const std::exception& ex) {
		outfile << "ERORR: exception " << ex.what() << std::endl;
	}
	catch (...) {
		outfile << "ERORR: Unknown failure occurred. Possible memory corruption " << std::endl;
	}


	return realNdrStubCall3(pThis, pChannel, pRpcMsg, pdwStubPhase);
}

void myNdrServerCallAll(PRPC_MESSAGE pRpcMsg)
{
	RPC_BINDING_HANDLE serverBinding;
	wchar_t* szStringBinding;
	UUID serverObjectUuid;
	RPC_CSTR szStringUuid;
	UUID* uuidPointer;
	byte* byteUuidPointer;
	unsigned char uuidData[20];
	std::wostringstream rpcEventLine;
	std::wstring szWstringBinding;
	try {

		RPC_STATUS status = RpcBindingServerFromClient(0, &serverBinding);
		if (status == RPC_S_OK) {

			status = RpcBindingToStringBinding(serverBinding, (RPC_WSTR*)&szStringBinding);
			if (status == RPC_S_OK) {
				if (wcsstr(szStringBinding, L"ncacn_ip_tcp") || wcsstr(szStringBinding, L"ncacn_nb_tcp") || wcsstr(szStringBinding, L"ncacn_np")) {
					rpcEventLine << L"myNdrServerCallAll,";
					//wcsncpy_s(wcsstr(szStringBinding, L":"), 1, L",", 1);
					//outfile << "myNdrServerCallAll called, ...\n" << std::endl;
					//outfile << szStringBinding << std::endl;
					szWstringBinding = std::wstring(szStringBinding);
					size_t pos = szWstringBinding.find(L":", 0);
					if (pos != std::string::npos) {
						szWstringBinding.replace(pos, 1, L",");
					}
					rpcEventLine << szWstringBinding << ",";


					status = RpcBindingInqObject(serverBinding, &serverObjectUuid);
					if (status == RPC_S_OK) {
						byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

						memcpy(&uuidData, byteUuidPointer + 4, 20);
						//outfile << "UUID: " << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6) << std::endl;
						rpcEventLine << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6);
						rpcEventLine << "," << std::to_wstring(pRpcMsg->ProcNum);
						outfile << rpcEventLine.str() << std::endl;
					}
					else
					{
						outfile << "RpcBindingInqObject failed....: " << std::endl;
					}
				}
			}
			else {
				outfile << "Not good:(\n" << std::endl;
			}
		}
	}
	catch (const std::runtime_error& re) {
		outfile << "ERORR: runtime " << re.what() << std::endl;
	}
	catch (const std::exception& ex) {
		outfile << "ERORR: exception " << ex.what() << std::endl;
	}
	catch (...) {
		outfile << "ERORR: Unknown failure occurred. Possible memory corruption " << std::endl;
	}
	return realNdrServerCallAll(pRpcMsg);
}

void myNdrAsyncServerCall(PRPC_MESSAGE pRpcMsg)
{
	RPC_BINDING_HANDLE serverBinding;
	wchar_t* szStringBinding;
	UUID serverObjectUuid;
	RPC_CSTR szStringUuid;
	UUID* uuidPointer;
	byte* byteUuidPointer;
	unsigned char uuidData[20];
	std::wostringstream rpcEventLine;
	std::wstring szWstringBinding;

	try {
		RPC_STATUS status = RpcBindingServerFromClient(0, &serverBinding);
		if (status == RPC_S_OK) {

			status = RpcBindingToStringBinding(serverBinding, (RPC_WSTR*)&szStringBinding);
			if (status == RPC_S_OK) {
				if (wcsstr(szStringBinding, L"ncacn_ip_tcp") || wcsstr(szStringBinding, L"ncacn_nb_tcp") || wcsstr(szStringBinding, L"ncacn_np")) {
					rpcEventLine << L"NdrAsyncServerCall,";
					//wcsncpy_s(wcsstr(szStringBinding, L":"), 1, L",", 1);
					//outfile << "myNdrServerCallAll called, ...\n" << std::endl;
					//outfile << szStringBinding << std::endl;
					szWstringBinding = std::wstring(szStringBinding);
					size_t pos = szWstringBinding.find(L":", 0);
					if (pos != std::string::npos) {
						szWstringBinding.replace(pos, 1, L",");
					}
					rpcEventLine << szWstringBinding << ",";


					status = RpcBindingInqObject(serverBinding, &serverObjectUuid);
					if (status == RPC_S_OK) {
						byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

						memcpy(&uuidData, byteUuidPointer + 4, 20);
						//outfile << "UUID: " << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6) << std::endl;
						rpcEventLine << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6);
						rpcEventLine << "," << std::to_wstring(pRpcMsg->ProcNum);
						outfile << rpcEventLine.str() << std::endl;
					}
					else
					{
						outfile << "RpcBindingInqObject failed....: " << std::endl;
					}
				}
			}
			else {
				outfile << "Not good:(\n" << std::endl;
			}
		}
	}
	catch (const std::runtime_error& re) {
		outfile << "ERORR: runtime " << re.what() << std::endl;
	}
	catch (const std::exception& ex) {
		outfile << "ERORR: exception " << ex.what() << std::endl;
	}
	catch (...) {
		outfile << "ERORR: Unknown failure occurred. Possible memory corruption " << std::endl;
	}
	return realNdrAsyncServerCall(pRpcMsg);
}

void myNdr64AsyncServerCallAll(PRPC_MESSAGE pRpcMsg)
{
	RPC_BINDING_HANDLE serverBinding;
	wchar_t* szStringBinding;
	UUID serverObjectUuid;
	RPC_CSTR szStringUuid;
	UUID* uuidPointer;
	byte* byteUuidPointer;
	unsigned char uuidData[20];
	std::wostringstream rpcEventLine;
	std::wstring szWstringBinding;

	try {

		RPC_STATUS status = RpcBindingServerFromClient(0, &serverBinding);
		if (status == RPC_S_OK) {

			status = RpcBindingToStringBinding(serverBinding, (RPC_WSTR*)&szStringBinding);
			if (status == RPC_S_OK) {
				if (wcsstr(szStringBinding, L"ncacn_ip_tcp") || wcsstr(szStringBinding, L"ncacn_nb_tcp") || wcsstr(szStringBinding, L"ncacn_np")) {
					rpcEventLine << L"Ndr64AsyncServerCallAll,";
					//wcsncpy_s(wcsstr(szStringBinding, L":"), 1, L",", 1);
					//outfile << "myNdrServerCallAll called, ...\n" << std::endl;
					//outfile << szStringBinding << std::endl;
					szWstringBinding = std::wstring(szStringBinding);
					size_t pos = szWstringBinding.find(L":", 0);
					if (pos != std::string::npos) {
						szWstringBinding.replace(pos, 1, L",");
					}
					rpcEventLine << szWstringBinding << ",";


					status = RpcBindingInqObject(serverBinding, &serverObjectUuid);
					if (status == RPC_S_OK) {
						byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

						memcpy(&uuidData, byteUuidPointer + 4, 20);
						//outfile << "UUID: " << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6) << std::endl;
						rpcEventLine << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6);
						rpcEventLine << "," << std::to_wstring(pRpcMsg->ProcNum);
						outfile << rpcEventLine.str() << std::endl;
					}
					else
					{
						outfile << "RpcBindingInqObject failed....: " << std::endl;
					}
				}
			}
			else {
				outfile << "Not good:(\n" << std::endl;
			}
		}
	}
	catch (const std::runtime_error& re) {
		outfile << "ERORR: runtime " << re.what() << std::endl;
	}
	catch (const std::exception& ex) {
		outfile << "ERORR: exception " << ex.what() << std::endl;
	}
	catch (...) {
		outfile << "ERORR: Unknown failure occurred. Possible memory corruption " << std::endl;
	}
	return realNdr64AsyncServerCallAll(pRpcMsg);
}

void myNdr64AsyncServerCall64(PRPC_MESSAGE pRpcMsg)
{
	RPC_BINDING_HANDLE serverBinding;
	wchar_t* szStringBinding;
	UUID serverObjectUuid;
	RPC_CSTR szStringUuid;
	UUID* uuidPointer;
	byte* byteUuidPointer;
	unsigned char uuidData[20];
	std::wostringstream rpcEventLine;
	std::wstring szWstringBinding;

	try {

		RPC_STATUS status = RpcBindingServerFromClient(0, &serverBinding);
		if (status == RPC_S_OK) {

			status = RpcBindingToStringBinding(serverBinding, (RPC_WSTR*)&szStringBinding);
			if (status == RPC_S_OK) {
				if (wcsstr(szStringBinding, L"ncacn_ip_tcp") || wcsstr(szStringBinding, L"ncacn_nb_tcp") || wcsstr(szStringBinding, L"ncacn_np")) {
					rpcEventLine << L"Ndr64AsyncServerCall64,";
					//wcsncpy_s(wcsstr(szStringBinding, L":"), 1, L",", 1);
					//outfile << "myNdrServerCallAll called, ...\n" << std::endl;
					//outfile << szStringBinding << std::endl;
					szWstringBinding = std::wstring(szStringBinding);
					size_t pos = szWstringBinding.find(L":", 0);
					if (pos != std::string::npos) {
						szWstringBinding.replace(pos, 1, L",");
					}
					rpcEventLine << szWstringBinding << ",";


					status = RpcBindingInqObject(serverBinding, &serverObjectUuid);
					if (status == RPC_S_OK) {
						byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

						memcpy(&uuidData, byteUuidPointer + 4, 20);
						//outfile << "UUID: " << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6) << std::endl;
						rpcEventLine << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6);
						rpcEventLine << "," << std::to_wstring(pRpcMsg->ProcNum);
						outfile << rpcEventLine.str() << std::endl;
					}
					else
					{
						outfile << "RpcBindingInqObject failed....: " << std::endl;
					}
				}
			}
			else {
				outfile << "Not good:(\n" << std::endl;
			}
		}
	}
	catch (const std::runtime_error& re) {
		outfile << "ERORR: runtime " << re.what() << std::endl;
	}
	catch (const std::exception& ex) {
		outfile << "ERORR: exception " << ex.what() << std::endl;
	}
	catch (...) {
		outfile << "ERORR: Unknown failure occurred. Possible memory corruption " << std::endl;
	}
	return realNdr64AsyncServerCall64(pRpcMsg);
}

void myNdrServerCallNdr64(PRPC_MESSAGE pRpcMsg)
{
	RPC_BINDING_HANDLE serverBinding;
	wchar_t* szStringBinding;
	UUID serverObjectUuid;
	RPC_CSTR szStringUuid;
	UUID* uuidPointer;
	byte* byteUuidPointer;
	unsigned char uuidData[20];
	std::wostringstream rpcEventLine;
	std::wstring szWstringBinding;

	try {

		RPC_STATUS status = RpcBindingServerFromClient(0, &serverBinding);
		if (status == RPC_S_OK) {

			status = RpcBindingToStringBinding(serverBinding, (RPC_WSTR*)&szStringBinding);
			if (status == RPC_S_OK) {
				if (wcsstr(szStringBinding, L"ncacn_ip_tcp") || wcsstr(szStringBinding, L"ncacn_nb_tcp") || wcsstr(szStringBinding, L"ncacn_np")) {
					rpcEventLine << L"NdrServerCallNdr64,";
					//wcsncpy_s(wcsstr(szStringBinding, L":"), 1, L",", 1);
					//outfile << "myNdrServerCallAll called, ...\n" << std::endl;
					//outfile << szStringBinding << std::endl;
					szWstringBinding = std::wstring(szStringBinding);
					size_t pos = szWstringBinding.find(L":", 0);
					if (pos != std::string::npos) {
						szWstringBinding.replace(pos, 1, L",");
					}
					rpcEventLine << szWstringBinding << ",";


					status = RpcBindingInqObject(serverBinding, &serverObjectUuid);
					if (status == RPC_S_OK) {
						byteUuidPointer = (byte*)pRpcMsg->RpcInterfaceInformation;

						memcpy(&uuidData, byteUuidPointer + 4, 20);
						//outfile << "UUID: " << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6) << std::endl;
						rpcEventLine << hexStr(&uuidData[3], 1) << hexStr(&uuidData[2], 1) << hexStr(&uuidData[1], 1) << hexStr(&uuidData[0], 1) << "-" << hexStr(&uuidData[5], 1) << hexStr(&uuidData[4], 1) << "-" << hexStr(&uuidData[7], 1) << hexStr(&uuidData[6], 1) << "-" << hexStr(&uuidData[8], 2) << "-" << hexStr(&uuidData[10], 6);
						rpcEventLine << "," << std::to_wstring(pRpcMsg->ProcNum);
						outfile << rpcEventLine.str() << std::endl;
					}
					else
					{
						outfile << "RpcBindingInqObject failed....: " << std::endl;
					}
				}
			}
			else {
				outfile << "Not good:(\n" << std::endl;
			}
		}
	}
	catch (const std::runtime_error& re) {
		outfile << "ERORR: runtime " << re.what() << std::endl;
	}
	catch (const std::exception& ex) {
		outfile << "ERORR: exception " << ex.what() << std::endl;
	}
	catch (...) {
		outfile << "ERORR: Unknown failure occurred. Possible memory corruption " << std::endl;
	}
	return realNdrServerCallNdr64(pRpcMsg);
}

void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

DWORD InjectionEntryPoint()
{
	try {
		FILE* fptr;
		//fptr = fopen("c:\\rpcrawler.log", "a+");
		//if (fptr != NULL) {
//			fprintf(fptr,"HELLO!\n");
		//}
		//fclose(fptr);
		
		/*outfile.open("rpcrawler.log", std::ios_base::app);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourAttach(&(PVOID&)realNdrStubCall2, myNdrStubCall2);
		DetourAttach(&(PVOID&)realNdrStubCall3, myNdrStubCall3);
		DetourAttach(&(PVOID&)realNdrServerCallAll, myNdrServerCallAll);
		DetourAttach(&(PVOID&)realNdrAsyncServerCall, myNdrAsyncServerCall);
		DetourAttach(&(PVOID&)realNdr64AsyncServerCallAll, myNdr64AsyncServerCallAll);
		DetourAttach(&(PVOID&)realNdr64AsyncServerCall64, myNdr64AsyncServerCall64);
		DetourAttach(&(PVOID&)realNdrServerCallNdr64, myNdrServerCallNdr64);


		if (DetourTransactionCommit() == NO_ERROR)
			OutputDebugString(TEXT("Detoured successfully"));*/
	}
	catch (int e) {
		TCHAR moduleName[128] = L"";
		GetModuleFileName(NULL, moduleName, sizeof(moduleName));
		ErrorExit(moduleName);
		//MessageBoxA(NULL, "An exception occurred.Exception Nr. " + e , moduleName, NULL);
	}

	return 0;
}