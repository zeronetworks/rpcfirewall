#pragma once

void tryAndRunElevated(DWORD pid);

void elevateCurrentProcessToSystem();

bool setSecurityPrivilege(const wchar_t*);