#pragma once
#include "stdafx.h"

void WINAPI serviceMain(DWORD, LPTSTR*);

DWORD WINAPI serviceWorkerThread(LPVOID);

void WINAPI serviceCtrlHandler(DWORD);

void writeDebugMessage(const wchar_t*);

bool setupService();

void serviceInstall(DWORD);

void serviceStop();

void serviceUninstall();

void serviceStart();

void serviceMakeAutostart();

bool isServiceInstalled();

void serviceMakeManual();

void printServiceState();