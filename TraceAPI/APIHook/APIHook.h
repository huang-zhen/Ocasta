// APIHOOK.H
// by James Huang 
// Nov.16, 2002
// Nov.15, 2011
//
#ifndef APIHOOK_H
#define APIHOOK_H

#include "Log.h"

extern "C" DWORD WINAPI HookAPI(PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnHook, PROC *ppfnOrig);
extern "C" void WINAPI UnHookAPI(DWORD handle);
extern "C" BOOL WINAPI OpenHookLib(HMODULE hmod, Log *pLog = NULL);
extern "C" void WINAPI CloseHookLib();
extern "C" void WINAPI InjectAllProcesses();
extern "C" char *pszExcludeProgName; // User can specify the program name which should be excluded from hooking
#endif // APIHOOK_H

