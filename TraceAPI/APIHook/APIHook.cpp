// APIHook.CPP
// Copyright (C) 2016 Zhen Huang
// Nov.16, 2002
//
#include <windows.h>
#include <imagehlp.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "Log.h"
#include "APIHook.h"

#pragma comment(lib, "ImageHlp")
//
char *pszExcludeProgName = NULL;
// Main Module Filename
static char mainModuleName[MAX_PATH]= "";
// The highest private memory address (used for Windows 98 only)
static PVOID sm_pvMaxAppAddr = NULL;
// The PUSH opcode on x86 platforms
const BYTE cPushOpCode = 0x68;
//
// Original API function entries
static FARPROC (WINAPI *GetProcAddressRaw)(HMODULE hmod, PCSTR pszProcName) ;
static HMODULE (WINAPI *LoadLibraryARaw)(PCSTR pszModulePath);
static HMODULE (WINAPI *LoadLibraryWRaw)(PCWSTR pszModulePath);
static HMODULE (WINAPI *LoadLibraryExARaw)(PCSTR pszModulePath, HANDLE hFile, DWORD dwFlags);
static HMODULE (WINAPI *LoadLibraryExWRaw)(PCWSTR pszModulePath, HANDLE hFile, DWORD dwFlags);
static BOOL (WINAPI *CreateProcessARaw)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
			BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
static BOOL (WINAPI *CreateProcessWRaw)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
			BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);

// Note: use my own version instead the one of CRT library
char* lstrrchrA(char *string, int c);
//
struct APIHookEntry {
  APIHookEntry(PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnOrig, PROC pfnHook);
  DWORD handle;
  char calleeModName[MAX_PATH];
  char funcName[MAX_PATH];
  PROC origFunc;
  PROC hookFunc;
  APIHookEntry *nextEntry;
};

static APIHookEntry *m_pHookEntryHead = NULL; // API Hook entry list head

// Initialization
class CLibInit {
public:
  CLibInit();
  ~CLibInit();
private:
// variables

};

//static CLibInit g_init;
static CRITICAL_SECTION g_sect;
static Log *g_log = NULL;
//
#define APIHOOKLOG
#ifdef APIHOOKLOG
#define APILOG if (g_log) g_log->print
#else
#define APILOG
#endif
//
APIHookEntry::APIHookEntry(PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnOrig, PROC pfnHook) {
  if (m_pHookEntryHead == NULL) handle = 1;
  else handle = m_pHookEntryHead->handle + 1;

  //int lenCalleeModName = lstrlenA(pszCalleeModName);
  //lstrcpyA(calleeModName, pszCalleeModName);
  strncpy(calleeModName, pszCalleeModName, sizeof(calleeModName));
  calleeModName[sizeof(calleeModName) - 1] = '\0';

  //int lenFuncName = lstrlenA(pszFuncName);
  //lstrcpyA(funcName, pszFuncName);
  strncpy(funcName, pszFuncName, sizeof(funcName));
  funcName[sizeof(funcName) - 1] = '\0';

  hookFunc = pfnHook;
  origFunc = pfnOrig;
  nextEntry = NULL;
}
//
static char* lstrrchrA(char *string, int c)
{
  char *pCh, *pStr = NULL;

  pCh = &string[lstrlenA(string)];
  while (pCh >= string) {
    if (*pCh == c) {
      pStr = pCh;
      break;
    }
    pCh--;
  }
  return pStr;
}
// 
static void GetMainModuleName()
{
  // This module should only be executed once
  char moduleName[MAX_PATH];
  GetModuleFileName(NULL, moduleName, MAX_PATH - 1);
  char *pFile = strrchr(moduleName, '\\');
  if (pFile == NULL)
    pFile = moduleName;
  else
    pFile ++;
  char *pExt = strrchr(moduleName, '.');
  if (pExt == NULL)
    pExt = moduleName + lstrlenA(moduleName);
  int length = pExt - pFile;
  memcpy(mainModuleName, pFile, length);
  mainModuleName[length] = '\0';
}

// Note: This function must NOT be inlined
//static FARPROC GetProcAddressRaw(HMODULE hmod, PCSTR pszProcName) {
//  return ::GetProcAddress(hmod, pszProcName);
//}

// Returns the HMODULE that contains the specified memory address
static HMODULE ModuleFromAddress(PVOID pv) {
  MEMORY_BASIC_INFORMATION mbi;

  return ((VirtualQuery(pv, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
}

// Macro for adding pointers/DWORDs together
#define MakePtr(cast, ptr, addValue) (cast)((DWORD)(ptr) + (DWORD)(addValue))

static BOOL WINAPI ReplaceIATEntryInOneMod(PCSTR pszCalleeModName, 
                                            PROC pfnCurrent,
                                            PROC pfnNew,
                                            HMODULE hmodCaller,
											PCSTR pszModName)
{
  if (IsBadCodePtr(pfnNew)) // Verify that a valid pfn was passed
    return FALSE;

  if (!pfnCurrent) // Verify the function address is valid
    return FALSE;

  //Get the address of the module's import section
  ULONG ulSize;
  PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)
    ImageDirectoryEntryToData(hmodCaller, TRUE, 
    IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
  if (pImportDesc == NULL)
    return FALSE; // This module has no import section

  // Find the import descriptor containing references to callee's functions
  for (; pImportDesc->Name; pImportDesc++) {
    PSTR pszModName = (PSTR) ((PBYTE) hmodCaller + pImportDesc->Name);
    if (lstrcmpiA(pszModName, pszCalleeModName) == 0)
      break; // Found
  }
  if (pImportDesc->Name == 0)
    return FALSE; // This module doesn't import any functions from this callee

  // Get caller's import address table (IAT) for the callee's functions
  PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
    ((PBYTE) hmodCaller + pImportDesc->FirstThunk);
  // Replace current function address with new function address
  for (; pThunk->u1.Function; pThunk++) {
    // Get the address of the function address
    PROC* ppfn = (PROC*) &pThunk->u1.Function;
    // Is this the function we're looking for?
    BOOL fFound = (*ppfn == pfnCurrent);
    if (!fFound && (*ppfn > sm_pvMaxAppAddr)) {
      // If this is not the function and the address is in a shared DLL
      // then maybe we're running under a debugger on Windows 98. In this
      // case, this address points to an instruction that may have the 
      // correct address
      PBYTE pbInFunc = (PBYTE)*ppfn;
      if (pbInFunc[0] == cPushOpCode) {
        // We see the PUSH instruction, the real function address follows
        ppfn = (PROC *)&pbInFunc[1];
        // Is this the function we're looking for?
        fFound = (*ppfn == pfnCurrent);
      }
    }
    if (fFound) {
				MEMORY_BASIC_INFORMATION mbi;
				::VirtualQuery(ppfn, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				// In order to provide writable access to this part of the 
				// memory we need to change the memory protection
				if (FALSE == ::VirtualProtect(
					mbi.BaseAddress,
					mbi.RegionSize,
					PAGE_EXECUTE_READWRITE,
					&mbi.Protect)
					)
					break;
				// Hook the function.
        (PROC)*ppfn = (PROC)*pfnNew;
				// Restore the protection back
        DWORD dwOldProtect;
				::VirtualProtect(
					mbi.BaseAddress,
					mbi.RegionSize,
					mbi.Protect,
					&dwOldProtect
					);
#if 0
        APILOG("replace %s:%X  with %X in module %s\n",
                      pszCalleeModName, 
                      (DWORD)pfnCurrent,
                      (DWORD)pfnNew,
                      pszModName);
#endif
        return TRUE;
    }
  }
  // If we get here, the function is not in the caller's import section
  return FALSE;
}

static BOOL WINAPI ReplaceIATEntryInAllMods(PCSTR pszCalleeModName, 
                                            PROC pfnCurrent,
                                            PROC pfnNew)
{
  BOOL result = FALSE;

  HMODULE hmodThisMod = ModuleFromAddress(ReplaceIATEntryInAllMods);
  HANDLE moduleSnap;
  MODULEENTRY32 moduleEntry;
  moduleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
  moduleEntry.dwSize = sizeof(moduleEntry);
  for (BOOL fOk = Module32First(moduleSnap, &moduleEntry); fOk; fOk = Module32Next(moduleSnap, &moduleEntry)) {
    // Note: Don't hook modules in shared area since we're not there
    if (moduleEntry.hModule != hmodThisMod && moduleEntry.hModule < sm_pvMaxAppAddr) {
		if (ReplaceIATEntryInOneMod(pszCalleeModName, pfnCurrent, pfnNew, moduleEntry.hModule, moduleEntry.szModule))
        result = TRUE;
    }
  }
  CloseHandle(moduleSnap);
  return result;
}

static void WINAPI FixupNewlyLoadedModule(HMODULE hmod, DWORD dwFlags)
{
  // If a new module is loaded, hook the hooked functions
  if ((hmod != NULL) && ((dwFlags & LOAD_LIBRARY_AS_DATAFILE) == 0)) {
	EnterCriticalSection(&g_sect);
    for (APIHookEntry* pEntry = m_pHookEntryHead; pEntry != NULL; pEntry = pEntry->nextEntry) {
      ReplaceIATEntryInOneMod(pEntry->calleeModName, pEntry->origFunc, pEntry->hookFunc, hmod, NULL);
    }
	LeaveCriticalSection(&g_sect);
  }
}

BOOL WINAPI IsAPIHooked(PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnHook)
{
    for (APIHookEntry* pEntry = m_pHookEntryHead; pEntry != NULL; pEntry = pEntry->nextEntry) {
		if (lstrcmp(pEntry->calleeModName, pszCalleeModName) == 0 && lstrcmp(pEntry->funcName, pszFuncName) == 0)
			return TRUE;
    }
	return FALSE;
}

DWORD WINAPI HookAPI(PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnHook, PROC *ppfnOrig)
{
  DWORD handle = 0; // Invalid handle

  EnterCriticalSection(&g_sect);
  //if (IsAPIHooked(pszCalleeModName, pszFuncName, pfnHook))
  //	goto bail;

  if (sm_pvMaxAppAddr == NULL) {
    // Function with address above lpMaximumApplicationAddress require
    // special processing (Windows 98 only)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    sm_pvMaxAppAddr = si.lpMaximumApplicationAddress;
  }
  //if (mainModuleName[0] == '\0') GetMainModuleName();
  //if (pszExcludeProgName != NULL)
  //  if (lstrcmpiA(mainModuleName, pszExcludeProgName) == 0) return FALSE;
  PROC pfnOrigFunc = GetProcAddressRaw(GetModuleHandleA(pszCalleeModName), pszFuncName);
  if (pfnOrigFunc > sm_pvMaxAppAddr) {
    // The address is in a shared DLL; the address needs fixing up
    PBYTE pb = (PBYTE) pfnOrigFunc;
    if (pb[0] == cPushOpCode) {
      // Skip over the PUSH op code and grab the real address
      PVOID pv = * (PVOID *) &pb[1];
      pfnOrigFunc = (PROC) pv;
    }
  }
  *ppfnOrig = pfnOrigFunc;
  // Hook this function in all currently loaded modules
  if (ReplaceIATEntryInAllMods(pszCalleeModName, pfnOrigFunc, pfnHook)) {
    // Save information about this hooked function
    APIHookEntry *pEntry = new APIHookEntry(pszCalleeModName,
                                          pszFuncName,
                                          pfnOrigFunc,
                                          pfnHook);
    pEntry->nextEntry = m_pHookEntryHead;
    m_pHookEntryHead = pEntry;
    handle = pEntry->handle;
  }
  //APILOG("HookAPI %s:%s = %X\n", pszCalleeModName, pszFuncName, handle);
  LeaveCriticalSection(&g_sect);
  return handle;
}

void WINAPI UnHookAPI(DWORD handle)
{
  EnterCriticalSection(&g_sect);
  //APILOG("UnHookAPI %X\n", handle);
  if (handle > 0) {
    APIHookEntry *pPrevEntry = NULL, *pEntry = m_pHookEntryHead;
    // Find the handle corresponding entry
    while (pEntry) {
      if (pEntry->handle == handle) break;
      pPrevEntry = pEntry;
      pEntry = pEntry->nextEntry;
    }
    if (pEntry) {
      ReplaceIATEntryInAllMods(pEntry->calleeModName, pEntry->hookFunc, pEntry->origFunc);
      if (m_pHookEntryHead == pEntry)
        m_pHookEntryHead = pEntry->nextEntry;
      else
        pPrevEntry->nextEntry = pEntry->nextEntry;
      delete pEntry;
    }
  }
  LeaveCriticalSection(&g_sect);
}

UINT WINAPI UnHookAllAPI()
{
  UINT count = 0;
  APIHookEntry *pEntry = m_pHookEntryHead;

  EnterCriticalSection(&g_sect);
  APILOG("UnHookAllAPI\n");
  while (pEntry != NULL) {
    if (ReplaceIATEntryInAllMods(pEntry->calleeModName, pEntry->hookFunc, pEntry->origFunc))
      count++;
    APIHookEntry *pPrevEntry = pEntry;
    pEntry = pEntry->nextEntry;
    delete pPrevEntry;
  }
  m_pHookEntryHead = NULL;
  LeaveCriticalSection(&g_sect);
  return count;
}

// Hook necessary API functions to assure functions be hooked in all modules
//
// Hook handles
static DWORD Hook_LoadLibraryAHandle = 0;
static DWORD Hook_LoadLibraryWHandle = 0;
static DWORD Hook_LoadLibraryExAHandle = 0;
static DWORD Hook_LoadLibraryExWHandle = 0;
static DWORD Hook_GetProcAddressHandle = 0;
static DWORD Hook_CreateProcessAHandle = 0;
static DWORD Hook_CreateProcessWHandle = 0;

// Original functions
static HMODULE (WINAPI *LoadLibraryAOrig)(PCSTR pszModulePath);
static HMODULE (WINAPI *LoadLibraryWOrig)(PCWSTR pszModulePath);
static HMODULE (WINAPI *LoadLibraryExAOrig)(PCSTR pszModulePath, HANDLE hFile, DWORD dwFlags);
static HMODULE (WINAPI *LoadLibraryExWOrig)(PCWSTR pszModulePath, HANDLE hFile, DWORD dwFlags);
static FARPROC (WINAPI *GetProcAddressOrig)(HMODULE hmod, PCSTR pszProcName);
static BOOL (WINAPI *CreateProcessAOrig)(
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFO lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation);
static BOOL (WINAPI *CreateProcessWOrig)(
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFO lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation);

// Hook functions
static HMODULE WINAPI Hook_LoadLibraryA(PCSTR pszModulePath);
static HMODULE WINAPI Hook_LoadLibraryW(PCWSTR pszModulePath);
static HMODULE WINAPI Hook_LoadLibraryExA(PCSTR pszModulePath, HANDLE hFile, DWORD dwFlags);
static HMODULE WINAPI Hook_LoadLibraryExW(PCWSTR pszModulePath, HANDLE hFile, DWORD dwFlags);
static FARPROC WINAPI Hook_GetProcAddress(HMODULE hmod, PCSTR pszProcName);
static BOOL WINAPI Hook_CreateProcessA(
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFO lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation);
static BOOL WINAPI Hook_CreateProcessW(
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFO lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation);


static HMODULE g_hKernMod = NULL;
static WCHAR g_modStr[MAX_PATH];

BOOL WINAPI OpenHookLib(HMODULE hmod, Log* pLog)
{
#ifdef APIHOOKLOG
  g_log = pLog;
#endif
  BOOL ret = FALSE;

  APILOG("%s\n", __FUNCTION__);
  InitializeCriticalSection(&g_sect);
  EnterCriticalSection(&g_sect);
  g_hKernMod = LoadLibrary("kernel32.dll");
  if (g_hKernMod) {
	  GetProcAddressRaw = (FARPROC (WINAPI *)(HMODULE, PCSTR))GetProcAddress(g_hKernMod, "GetProcAddress");
	  LoadLibraryWRaw = (HMODULE (WINAPI *)(PCWSTR))GetProcAddress(g_hKernMod, "LoadLibraryW");
	  LoadLibraryExWRaw = (HMODULE (WINAPI *)(PCWSTR, HANDLE, DWORD))GetProcAddress(g_hKernMod, "LoadLibraryExW");
	  Hook_LoadLibraryWHandle   = HookAPI("kernel32.dll", "LoadLibraryW", (PROC)Hook_LoadLibraryW, (PROC *)&LoadLibraryWOrig);
	  Hook_LoadLibraryExWHandle = HookAPI("kernel32.dll", "LoadLibraryExW", (PROC)Hook_LoadLibraryExW, (PROC *)&LoadLibraryExWOrig);
	  Hook_GetProcAddressHandle = HookAPI("kernel32.dll", "GetProcAddress", (PROC)Hook_GetProcAddress, (PROC *)&GetProcAddressOrig);

	  if (hmod) {
		  GetModuleFileNameW(hmod, g_modStr, sizeof(g_modStr)/sizeof(WCHAR));
		  CreateProcessWRaw = (BOOL (WINAPI *)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
				BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION))GetProcAddress(g_hKernMod, "CreateProcessW");;
		  Hook_CreateProcessWHandle = HookAPI("kernel32.dll", "CreateProcessW", (PROC)Hook_CreateProcessW, (PROC *)&CreateProcessWOrig);
		  //APILOG("%s Hook_CreateProcessWHandle %X\n", __FUNCTION__, Hook_CreateProcessWHandle);
	  } else
		  APILOG("%s hmod is NULL\n", __FUNCTION__);
	  ret = TRUE;
  }
  LeaveCriticalSection(&g_sect);
  return ret;
}

void WINAPI CloseHookLib()
{
  APILOG("%s\n", __FUNCTION__);
  UnHookAllAPI();
  if (g_hKernMod)
	  FreeLibrary(g_hKernMod);
  DeleteCriticalSection(&g_sect);
}

CLibInit::CLibInit() {
  //Hook_LoadLibraryAHandle   = HookAPI("Kernel32.dll", "LoadLibraryA", (PROC)Hook_LoadLibraryA, (PROC *)&LoadLibraryAOrig);
  //Hook_LoadLibraryWHandle   = HookAPI("Kernel32.dll", "LoadLibraryW", (PROC)Hook_LoadLibraryW, (PROC *)&LoadLibraryWOrig);
  //Hook_LoadLibraryExAHandle = HookAPI("Kernel32.dll", "LoadLibraryExA", (PROC)Hook_LoadLibraryExA, (PROC *)&LoadLibraryExAOrig);
  //Hook_LoadLibraryExWHandle = HookAPI("Kernel32.dll", "LoadLibraryExW", (PROC)Hook_LoadLibraryExW, (PROC *)&LoadLibraryExWOrig);
  //Hook_GetProcAddressHandle = HookAPI("Kernel32.dll", "GetProcAddress", (PROC)Hook_GetProcAddress, (PVOID *)GetProcAddressOrig);
}

CLibInit::~CLibInit() {
  //UnHookAPI(Hook_LoadLibraryAHandle);
  //UnHookAPI(Hook_LoadLibraryWHandle);
  //UnHookAPI(Hook_LoadLibraryExAHandle);
  //UnHookAPI(Hook_LoadLibraryExWHandle);
  //UnHookAPI(Hook_GetProcAddressHandle);
}

HMODULE WINAPI Hook_LoadLibraryA(PCSTR pszModulePath) {
  HMODULE hmod = LoadLibraryARaw(pszModulePath);
  FixupNewlyLoadedModule(hmod, 0);
  return hmod;
}

HMODULE WINAPI Hook_LoadLibraryW(PCWSTR pszModulePath) {
	char buf[MAX_PATH];
	_snprintf(buf, sizeof(buf), "\"%S\"", pszModulePath);
	buf[sizeof(buf) - 1] = '\0';
	APILOG("%s %s\n", __FUNCTION__, buf);

  HMODULE hmod = LoadLibraryWRaw(pszModulePath);
  FixupNewlyLoadedModule(hmod, 0);
  return hmod;
}

HMODULE WINAPI Hook_LoadLibraryExA(PCSTR pszModulePath, HANDLE hFile, DWORD dwFlags) {
  HMODULE hmod = LoadLibraryExARaw(pszModulePath, hFile, dwFlags);
  FixupNewlyLoadedModule(hmod, dwFlags);
  return hmod;
}

HMODULE WINAPI Hook_LoadLibraryExW(PCWSTR pszModulePath, HANDLE hFile, DWORD dwFlags) {
	char buf[MAX_PATH];
	_snprintf(buf, sizeof(buf), "0x%0X \"%S\"", dwFlags, pszModulePath);
	buf[sizeof(buf) - 1] = '\0';

  HMODULE hmod = LoadLibraryExWRaw(pszModulePath, hFile, dwFlags);
  FixupNewlyLoadedModule(hmod, dwFlags);
  return hmod;
}

FARPROC WINAPI Hook_GetProcAddress(HMODULE hmod, PCSTR pszProcName) {
  // Get the true address of the function
  FARPROC pfn = GetProcAddressRaw(hmod, pszProcName);
  // Is it one of the functions that we want hooked?
  for (APIHookEntry *pEntry = m_pHookEntryHead; pEntry != NULL; pEntry = pEntry->nextEntry) {
    if (pfn == pEntry->origFunc) {
      // The address to return matches an address we want to hook
      // Return the hook function address instead
      pfn = pEntry->hookFunc;
      break;
    }
  }
  return pfn;
}

BOOL WINAPI InjectLibW(HANDLE hProcess, PCWSTR pszLibFile)
{
	BOOL fOK = FALSE;
	HANDLE hThread = NULL;
	PWSTR pszLibFileRemote = NULL;

	int cch = lstrlenW(pszLibFile) + 1;
	int cb = cch * sizeof(WCHAR);
		
	APILOG("%s %d\n", __FUNCTION__, GetProcessId(hProcess));
	pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL) {
		APILOG("%s failed on VirtualAllocEx:%d\n", __FUNCTION__, GetLastError());
		goto bail;
	}

	if (!WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, cb, NULL)) {
		APILOG("%s failed on WriteProcessMemory:%d\n", __FUNCTION__, GetLastError());
		goto bail;
	}

	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)LoadLibraryWRaw;
	if (pfnThreadRtn == NULL) {
		APILOG("%s failed as LoadLibraryW is NULL\n", __FUNCTION__);
		goto bail;
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
	if (hThread == NULL) {
		APILOG("%s failed on CreateRemoteThread:%d\n", __FUNCTION__, GetLastError());
		goto bail;
	}

	WaitForSingleObject(hThread, INFINITE);
	fOK = TRUE;

bail:
	if (pszLibFileRemote)
		VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);	

	if (hThread)
		CloseHandle(hThread);

	return fOK;
}

BOOL WINAPI InjectLibExW(DWORD dwProcessId, PCWSTR pszLibFile)
{
	BOOL fOK = FALSE;
	HANDLE hProcess = NULL;

	hProcess = OpenProcess(
		(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE),
		FALSE, dwProcessId);
	if (hProcess != NULL) {
		fOK = InjectLibW(hProcess, pszLibFile);
		CloseHandle(hProcess);
	}
	return fOK;
}

#define USE_DEBUG_API

#ifdef USE_DEBUG_API

BOOL GetFileNameFromHandle(HANDLE hFile, PWSTR pszFilename, DWORD size) 
{
  BOOL bSuccess = FALSE;
  HANDLE hFileMap;

  // Get the file size.
  DWORD dwFileSizeHi = 0;
  DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi); 

  if( dwFileSizeLo == 0 && dwFileSizeHi == 0 )
  {
     APILOG("%s Cannot map a file with a length of zero.\n", __FUNCTION__);
     return FALSE;
  }

  // Create a file mapping object.
  hFileMap = CreateFileMapping(hFile, 
                    NULL, 
                    PAGE_READONLY,
                    0, 
                    1,
                    NULL);

  if (hFileMap) 
  {
    // Create a file mapping to get the file name.
    void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

    if (pMem) 
    {
      if (GetMappedFileNameW (GetCurrentProcess(), 
                             pMem, 
                             pszFilename,
                             size)) 
			bSuccess = TRUE;
	  else
			APILOG("%s GetMappedFileNameA failed\n", __FUNCTION__);
      UnmapViewOfFile(pMem);
    } 
    CloseHandle(hFileMap);
  } else
	  APILOG("%s CreateFileMapping failed\n", __FUNCTION__);
  return(bSuccess);
}

BOOL InjectDLL(HANDLE hProcess, LPCONTEXT pOrigContext, LPCWSTR dllPath, LPVOID *pRemoteCode, LPDWORD pRemoteCodeSize)
{
	BOOL ret = FALSE;
	BYTE instructions[] = 
	{	0xB8, 00, 00, 00, 00,	// mov EAX,  0h | Pointer to LoadLibraryW() (DWORD)
		0xBB, 00, 00, 00, 00,	// mov EBX,  0h | DLLName to inject (DWORD)
		0x53,					// push EBX
		0xFF, 0xD0,				// call EAX
		//0x5b,					// pop EBX
#ifdef HIJACK_EXISTING_THREAD
		0xcc,					// INT 3h
#else
		0xc2, 0x04, 0x00		// ret 4
#endif
	};
	BYTE buf[sizeof(instructions) + MAX_PATH];
	int sizeCode = sizeof(instructions);
	CONTEXT context;
	
	int sizeDllPath = (lstrlenW(dllPath) + 1) * sizeof(WCHAR);
	int cb = sizeCode + sizeDllPath;

	PBYTE pCode = (PBYTE)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pCode == NULL) {
		APILOG("%s failed on VirtualAllocEx:%d\n", __FUNCTION__, GetLastError());
		goto bail;
	}

	*pRemoteCode = pCode;
	*pRemoteCodeSize = cb;

	memcpy(buf, instructions, sizeCode);

	PBYTE DLLName = (PBYTE)(buf + sizeCode);
	LPDWORD EAX = (LPDWORD)(buf + 1);
	LPDWORD EBX = (LPDWORD)(buf + 6);

	memcpy(DLLName, dllPath, sizeDllPath);
	*EAX = (DWORD)LoadLibraryWRaw;
	*EBX = (DWORD)(pCode + sizeCode);

	if (!WriteProcessMemory(hProcess, pCode, buf, cb, NULL)) {
		APILOG("%s failed on WriteProcessMemory:%d\n", __FUNCTION__, GetLastError());
		goto bail;
	}
	FlushInstructionCache(hProcess, pCode, cb);
#ifdef HIJACK_EXISTING_THREAD
	context = *pOrigContext;
	context.ContextFlags = CONTEXT_FULL;
	context.Eip = (DWORD)pCode;
	ret = SetThreadContext(hThread, &context);
#else
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pCode, NULL, 0, NULL);
	if (hThread == NULL) {
		APILOG("%s failed on CreateRemoteThread:%d\n", __FUNCTION__, GetLastError());
		goto bail;
	}
#endif

bail:
	return ret;
}

BOOL DisableIsDebuggerPresent(HANDLE hProcess)
{
	PROC func = GetProcAddressRaw(GetModuleHandleA("kernel32.dll"), "IsDebuggerPresent");
	if (func) {
		BYTE instructions[] = {
			0x33, 0xc0,
			0xc3
		};
		return WriteProcessMemory(hProcess, func, instructions, sizeof(instructions), NULL);
	}
	return FALSE;
}

typedef struct _CreateProcThreadData {
  LPCWSTR lpApplicationName;
  LPWSTR lpCommandLine;
  LPSECURITY_ATTRIBUTES lpProcessAttributes;
  LPSECURITY_ATTRIBUTES lpThreadAttributes;
  BOOL bInheritHandles;
  DWORD dwCreationFlags;
  LPVOID lpEnvironment;
  LPCWSTR lpCurrentDirectory;
  LPSTARTUPINFO lpStartupInfo;
  LPPROCESS_INFORMATION lpProcessInformation;
#ifdef USE_CREATEPROC_THREAD
  HANDLE hEvent;
#endif
  DWORD dwResult;
  DWORD dwLastError;
} CreateProcThreadData;

void HandleDebugEvent(HANDLE hProcess, HANDLE hThread)
{
	DEBUG_EVENT dEvent;
	HMODULE baseImage = NULL;
	BOOL bHandled = FALSE; // set TRUE for debugging
	DWORD breakPointCount = 0;
	CONTEXT context;
	LPVOID pRemoteCode;
	DWORD remoteCodeSize;
#ifdef USE_CREATEPROC_THREAD
	BOOL bSignaled = FALSE;
	BOOL bSuspend = lp->dwCreationFlags & CREATE_SUSPENDED;
#endif

	DebugSetProcessKillOnExit(FALSE);
	for (;!bHandled;) {
		DWORD dwContinueStatus = DBG_CONTINUE;
		if (!WaitForDebugEvent(&dEvent, INFINITE))
			break;

		APILOG("%s %d 0x%0X WaitForDebugEvent %d\n", __FUNCTION__, dEvent.dwProcessId, 
			dEvent.dwThreadId, dEvent.dwDebugEventCode);
		if(dEvent.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)
		{
			baseImage = (HMODULE)dEvent.u.CreateProcessInfo.lpBaseOfImage;
			//CloseHandle(dEvent.u.CreateProcessInfo.hProcess);
			//CloseHandle(dEvent.u.CreateProcessInfo.hThread);
			CloseHandle(dEvent.u.CreateProcessInfo.hFile);
		}

		if(dEvent.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT) {
			break;
		}
#if 0
		// GetFileNameFromHandle seemed to invoke GetModuleFileName remotely and caused crash
		// since kernel32.dll may not be loaded yet
		if(dEvent.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT)
		{
			WCHAR filename[MAX_PATH];

			if (GetFileNameFromHandle(dEvent.u.LoadDll.hFile, filename, MAX_PATH)) {
				char buf[MAX_PATH];
				sprintf(buf, "%S", filename);
				APILOG("%s Load %s\n", __FUNCTION__, buf);
			}
			CloseHandle(dEvent.u.LoadDll.hFile);
		}
#endif
		if(dEvent.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT)
		{
			APILOG("%s %d 0x%0X CreateThread at 0x%0X\n", __FUNCTION__,
				dEvent.dwProcessId, dEvent.dwThreadId,
				dEvent.u.CreateThread.lpStartAddress);
			//CloseHandle(dEvent.u.CreateThread.hThread);
		}

		if(dEvent.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT)
		{
		}

		if(dEvent.dwDebugEventCode==EXCEPTION_DEBUG_EVENT)//Check for breakpoint
		{
			APILOG("%s %d 0x%0X Exception 0x%0X at 0x%0X\n", __FUNCTION__,
				dEvent.dwProcessId, dEvent.dwThreadId,
				dEvent.u.Exception.ExceptionRecord.ExceptionCode,
				dEvent.u.Exception.ExceptionRecord.ExceptionAddress);
			if(dEvent.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT)
			{//It is a break point;
				// assume it is the same main thread when process is created
				if (!bHandled) {
					breakPointCount++;
					if (breakPointCount == 1) {
						pRemoteCode = NULL;
						remoteCodeSize = 0;

						context.ContextFlags = CONTEXT_FULL;
						if (GetThreadContext(hThread, &context)) {
							DisableIsDebuggerPresent(hProcess);
							InjectDLL(hProcess, &context, g_modStr, &pRemoteCode, &remoteCodeSize);
							//InjectLibW(hProcess, g_modStr);
#ifndef HIJACK_EXISTING_THREAD
							bHandled = TRUE;
#endif
						} else
							APILOG("%s failed on GetThreadContext:%d\n", __FUNCTION__, GetLastError());

					} else if (breakPointCount == 2) {
						if (pRemoteCode) {
							if (!VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE))
								APILOG("%s failed on VirtualFreeEx:%d\n", __FUNCTION__, GetLastError());
						}
#ifdef HIJACK_EXISTING_THREAD
						CONTEXT newContext;
						newContext.ContextFlags = CONTEXT_FULL;
						if (GetThreadContext(hThread, &newContext)) {
							APILOG("%s remote LoadLibraryW returned %0X\n", __FUNCTION__, newContext.Eax);
						} else
							APILOG("%s failed on GetThreadContext:%d\n", __FUNCTION__, GetLastError());
						SetThreadContext(hThread, pOrigContext);
#endif
#ifdef USE_CREATEPROC_THREAD
						if (bSuspend)
							SuspendThread(hThread);
#endif
						bHandled = TRUE;
#ifdef USE_CREATEPROC_THREAD
						SetEvent(lp->hEvent);
						bSignaled = TRUE;
#endif
					}
				} else {
					if (breakPointCount == 0) {
#ifdef USE_CREATEPROC_THREAD
						if (!bSignaled) {
							SetEvent(lp->hEvent);
							bSignaled = TRUE;
						}
#endif
						breakPointCount++;
					} else
						dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
			} else
			{
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
			}
		} // end if
		ContinueDebugEvent(dEvent.dwProcessId, dEvent.dwThreadId, dwContinueStatus);
	} // end for
#ifdef USE_CREATEPROC_THREAD
	if (!bSignaled)
		SetEvent(lp->hEvent);
#endif
}

BOOL InjectProcess(DWORD dwProcessId, HANDLE hProcess, HANDLE hThread)
{
	if (!DebugActiveProcess(dwProcessId)) {
		APILOG("%s DebugActiveProcess on %d failed\n", __FUNCTION__, dwProcessId);
#ifdef USE_CREATEPROC_THREAD
		SetEvent(lp->hEvent);
#endif
		return FALSE;
	}
	HandleDebugEvent(hProcess, hThread);
	DebugActiveProcessStop(dwProcessId);
	return TRUE;
}

DWORD WINAPI CreateProcThread(LPVOID lpParm)
{
	CreateProcThreadData* lp = (CreateProcThreadData *)lpParm;
	BOOL ret;

	ret = CreateProcessWRaw(lp->lpApplicationName, lp->lpCommandLine, lp->lpProcessAttributes, lp->lpThreadAttributes,
		lp->bInheritHandles, lp->dwCreationFlags | CREATE_SUSPENDED, lp->lpEnvironment, lp->lpCurrentDirectory, lp->lpStartupInfo, lp->lpProcessInformation);
	if (ret == FALSE) {
#ifdef USE_CREATEPROC_THREAD
		SetEvent(lp->hEvent);
#endif
		return 0;
	}
	APILOG("%s CreateProcessWRaw returns %d\n", __FUNCTION__, lp->lpProcessInformation->dwProcessId);
	ResumeThread(lp->lpProcessInformation->hThread);
	lp->dwLastError = GetLastError();
	lp->dwResult = 1;
	DWORD waitRet = WaitForInputIdle(lp->lpProcessInformation->hProcess, INFINITE);
	//Sleep(1);
	InjectProcess(lp->lpProcessInformation->dwProcessId,
		lp->lpProcessInformation->hProcess, 
		lp->lpProcessInformation->hThread 
		);
	return 1;
}
#endif

#if 0
BOOL WINAPI Hook_CreateProcessA(
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFO lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL ret;
	PROCESS_INFORMATION pi;

	char buf[MAX_PATH];
	_snprintf(buf, sizeof(buf), "0x%0X \"%s\" \"%s\"", dwCreationFlags, lpApplicationName, lpCommandLine);
	buf[sizeof(buf) - 1] = '\0';
	APILOG("%s %s\n", __FUNCTION__, buf);

	ret = CreateProcessARaw(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
				bInheritHandles, (dwCreationFlags | CREATE_SUSPENDED), lpEnvironment, lpCurrentDirectory, lpStartupInfo, &pi);
	if (ret) {
		if (g_modStr[0] != '\0')
			InjectLibW(pi.hProcess, g_modStr);
			//InjectLibExW(pi.dwProcessId, g_modStr);
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			DWORD count = ResumeThread(pi.hThread);
			if (count < 0)
				APILOG("%s ResumeThread:%d err:%d\n", __FUNCTION__, count, GetLastError());
		}
		if (lpProcessInformation)
			*lpProcessInformation = pi;
		else {
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}
	} else
		APILOG("%s CreateProcessARaw failed %d\n", __FUNCTION__, GetLastError());
	return ret;
}
#endif

BOOL WINAPI Hook_CreateProcessW(
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFO lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL ret = FALSE;

	char buf[MAX_PATH];
	_snprintf(buf, sizeof(buf), "0x%0X \"%S\" \"%S\"", dwCreationFlags, lpApplicationName, lpCommandLine);
	buf[sizeof(buf) - 1] = '\0';
	APILOG("%s %s\n", __FUNCTION__, buf);

#ifdef USE_DEBUG_API
	if (dwCreationFlags & (DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS))
		return CreateProcessWRaw(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
			bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	PROCESS_INFORMATION pi;
	CreateProcThreadData data;
	DWORD lastError = GetLastError();

	data.lpApplicationName = lpApplicationName;
	data.lpCommandLine = lpCommandLine;
	data.lpProcessAttributes = lpProcessAttributes;
	data.lpThreadAttributes = lpThreadAttributes;
	data.bInheritHandles = bInheritHandles;
	data.dwCreationFlags = dwCreationFlags;
	data.lpEnvironment = lpEnvironment;
	data.lpCurrentDirectory = lpCurrentDirectory;
	data.lpStartupInfo = lpStartupInfo;
	data.lpProcessInformation = &pi;
	data.dwResult = 0;
	data.dwLastError = GetLastError();

#ifdef USE_CREATEPROC_THREAD
	data.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	HANDLE hThread = CreateThread(NULL, 0, CreateProcThread, &data, 0, NULL);
	if (hThread) {
		CloseHandle(hThread);
		if (WaitForSingleObject(hEvent, 5000) != WAIT_OBJECT_0)
			APILOG("%s WaitForSingleObject failed: %d\n", __FUNCTION__, GetLastError());
		CloseHandle(hEvent);
#else
	CreateProcThread(&data);
#endif
		lastError = data.dwLastError;
		if (data.dwResult) {
			// process created successfully
			if (lpProcessInformation)
				*lpProcessInformation = pi;
			else {
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
			}
			ret = TRUE;
		}
#ifdef USE_CREATEPROC_THREAD
	} else
		APILOG("%s CreateThread failed\n", __FUNCTION__, GetLastError());
#endif
#else
	PROCESS_INFORMATION pi;

	ret = CreateProcessWRaw(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
				bInheritHandles, (dwCreationFlags | CREATE_SUSPENDED), lpEnvironment, lpCurrentDirectory, lpStartupInfo, &pi);
	DWORD lastError = GetLastError();
	if (ret) {
		if (g_modStr[0] != '\0')
			InjectLibW(pi.hProcess, g_modStr);
			//InjectLibExW(pi.dwProcessId, g_modStr);
		if (lpProcessInformation)
			*lpProcessInformation = pi;
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			DWORD count = ResumeThread(pi.hThread);
			if (count < 0)
				APILOG("%s ResumeThread:%d err:%d\n", __FUNCTION__, count, GetLastError());
		}
		if (!lpProcessInformation) {
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}
	} else
		APILOG("%s CreateProcessWRaw failed %d\n", __FUNCTION__, GetLastError());
#endif
	SetLastError(lastError);
	return ret;
}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    ) 
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    { 
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    } 

    return TRUE;
}

BOOL AdjustPrivilege()
{
	HANDLE hToken = NULL;
	HANDLE hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
	}
	return FALSE;
}

void WINAPI InjectAllProcesses()
{
	AdjustPrivilege();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32;

		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32)) {
			do {
				APILOG("%s %d %s\n", __FUNCTION__, pe32.th32ProcessID, pe32.szExeFile);
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
				if (hProcess) {
				//InjectProcess(
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
}
