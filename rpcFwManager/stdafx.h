#pragma once

#define _WIN32_WINNT 0x0602

#define INFO_BUFFER_SIZE 32767
#define MAX_RECORD_BUFFER_SIZE  0x10000 
#define LOW_INTEGRITY_SDDL_SACL_T       TEXT("S:(ML;;NW;;;LW)")
#define CONF_FILE_NAME TEXT("RpcFw.conf")
#define RPC_FW_DLL_NAME TEXT("rpcFireWall.dll")
#define RPC_MESSAGES_DLL_NAME TEXT("rpcMessages.dll")

#include <Windows.h>
#include <string>
#include <tchar.h>
#include <Tlhelp32.h>
#include <vector>
#include <comdef.h>

#include "Injections.h"
#include "rpcMessages.h"
#include "elevation.h"


