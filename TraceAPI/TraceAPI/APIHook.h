// APIHOOK.H
// Nov.16, 2002 by James Huang 
//
#ifndef APIHOOK_H
#define APIHOOK_H
#include <windows.h>
class CAPIHOOK {
public:
  DWORD HookAPI(PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnHook);
  UnHookAPI(DWORD handle);
  PROC OrigAPIFunc(DWORD handle);
private:
  struct _APIHookEntry {
    DWORD handle;
    PSTR pszCalleeModName;
    PSTR pszFuncName;
    PROC pfnOrigFunc;
    PROC pfnHookedFunc;
    _APIHookEntry *nextEntry;
  };
  _APIHookEntry *m_pHookEntry; // head of APIHook entries
};
#endif // APIHOOK_H