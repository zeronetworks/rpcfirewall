#pragma once
#include "stdafx.h"

#define SERVICE_NAME  _T("RPC Firewall")
extern HANDLE globalMappedMemory;
extern HANDLE globalUnprotectEvent;
extern bool interactive;

std::wstring getFullPathOfFile(const std::wstring&);

void writeDebugMessage(const wchar_t*);

void outputMessage(const wchar_t*);

void outputMessage(const wchar_t*, DWORD);

bool createSecurityAttributes(SECURITY_ATTRIBUTES*, PSECURITY_DESCRIPTOR);

HANDLE createGlobalEvent(bool, bool, wchar_t*);

void createAllGloblEvents();

void readConfigAndMapToMemory();

CHAR* readConfigFile(DWORD*);

void printMappedMeomryConfiguration();

std::wstring StringToWString(const std::string&);

std::tuple<size_t, size_t, bool> getConfigOffsets(std::string);