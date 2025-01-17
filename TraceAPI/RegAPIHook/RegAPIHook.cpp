// RegAPIHook.cpp : Defines the initialization routines for the DLL.
// Copyright (C) 2016 Zhen Huang
//
// Nov.18, 2002
// Nov.8, 2011
// The following allows WM_MOUSEWHEEL message to be defined
#define _WIN32_WINDOWS 0x500
//
#include <windows.h>
#include <richedit.h>
#include <Tlhelp32.h>
#include <limits.h>
#include "..\\APIHook\\APIHook.h"
#include "..\\APIHook\\Log.h"
#include "RegAPIHook.h"
#include "Resource.h"

// Declaration of global variables
HINSTANCE g_hModule = NULL;   // HANDLE of this module
HWND   g_hWnd = NULL;      // 
HANDLE g_hHeap = NULL;     // Heap Handle
BOOL   g_bHooked = FALSE;
HWND   g_hwndDlg = NULL;
POINT  g_curMousePos;
HWND   g_hHookedWnd;
UINT   g_nHookedWndType;
//char   g_appName[MAX_MODULE_NAME32 + 1];
char   g_logPath[MAX_PATH];
BOOL   g_procAttached = FALSE;
BOOL   g_bHookLib = FALSE;
Log	   RegAPILog(Log::MIN_LOG_BUFSIZE * 64);
//
static char appKeyName[] = "Software\\Sunbird\\TraceAPI";
static char mainWndName[] = "MainWindow";
static char hookAppName[] = "HookAppName";
static char logPath[] = "LogPath";

PVOID GetErrorMsg(DWORD err)
{
	PVOID lpMsgBuf = NULL;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0, NULL );
	return lpMsgBuf;
}

// Include source code generated by codegen
//
#include "reghook.c"

// Declaration of functions
BOOL SendMainWndMsg(DWORD dwType, BOOL bWideChar, PVOID lpStr, UINT cbCount);
UINT GetWndType(HWND hWnd);
//
LRESULT CALLBACK GetMsgProc(int code, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK Dlg_Proc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
/////////////////////////////////////////////////////////////////////////////
//
// Since we do DLL injection with Windows' hooks, we need to save the hook
// handle in a shared memory block (Windows 2000 actually doesn't need this)
// Instruct the linker that we want to share the data in this section with
// all instances of this application.
#pragma data_seg("Shared")
HHOOK g_hhook = NULL;
HWND  g_hMainWnd = NULL;
DWORD g_dwThreadID = 0;
#pragma data_seg()
// Instruct the linker to make the Shared section 
// readable, writeable and shared
#pragma comment(linker, "/SECTION:Shared,rws")
//
//
BOOL CreateDlg()
{
	BOOL ret;

    // Create the RegAPIHook Window to handle the client request
	if (g_hwndDlg == NULL) {
		g_hwndDlg = CreateDialog(g_hModule, MAKEINTRESOURCE(IDD_REGAPIHOOKDLG), NULL, (DLGPROC)Dlg_Proc);
		if (g_hwndDlg != NULL) {
		  char title[80];

		  _snprintf(title, sizeof(title), "RegAPIHookDlg:%d", GetCurrentProcessId());
		  SetWindowText(g_hwndDlg, title);
		  SetTimer(g_hwndDlg, 1, 10, NULL);
		  RegAPILog.print("Create %s\n", title);
		  ret = TRUE;
		} else {
		  DWORD err = GetLastError();
		  RegAPILog.print("Unable to create dialog:%s", GetErrorMsg(err));
		  ret = FALSE;
		}
	}
	return ret;
}

#if 0
BOOL NeedHookAPI()
{
	char modName[MAX_MODULE_NAME32 + 1];
	DWORD size = sizeof(modName);
	BOOL ret = FALSE;
	HKEY key;

	LONG lret = RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, KEY_QUERY_VALUE, &key);
	if (lret == ERROR_SUCCESS) {
		lret = RegQueryValueEx(key, hookAppName, NULL, NULL, (PBYTE)modName, &size);
		if (lret == ERROR_SUCCESS) {
			if (strcmp(g_appName, modName) == 0)
				ret = TRUE;
		}
		else {
			//PVOID lpMsgBuf = GetErrorMsg(lret);
			RegAPILog.print("Unable to get hookAppName\n");
			//LocalFree(lpMsgBuf);
		}
		RegCloseKey(key);
	} else {
			PVOID lpMsgBuf = GetErrorMsg(lret);
			RegAPILog.print("RegOpenKeyEx %s failed:%s\n", appKeyName, lpMsgBuf);
			LocalFree(lpMsgBuf);
	}
	return ret;
}
#endif

HWND GetMainWnd()
{
	HWND hWnd = NULL;
	HKEY key;
	DWORD size = sizeof(hWnd);

	LONG lret = RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, KEY_QUERY_VALUE, &key);
	if (lret == ERROR_SUCCESS) {
		lret = RegQueryValueEx(key, mainWndName, NULL, NULL, (PBYTE)&hWnd, &size);
		if (lret != ERROR_SUCCESS) {
			PVOID lpMsgBuf = GetErrorMsg(lret);
			RegAPILog.print("RegQueryValueEx %s\\MainWindow failed:%s\n", appKeyName, lpMsgBuf);
			LocalFree(lpMsgBuf);
			RegCloseKey(key);
		}
	} else {
			PVOID lpMsgBuf = GetErrorMsg(lret);
			RegAPILog.print("RegOpenKeyEx %s failed:%s\n", appKeyName, lpMsgBuf);
			LocalFree(lpMsgBuf);
	}
	return hWnd;
}

BOOL SetMainWnd(HWND hWnd)
{
	BOOL ret;
	HKEY key;

	LONG lret = RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, KEY_SET_VALUE, &key);
	if (lret == ERROR_SUCCESS) {
		g_hMainWnd = hWnd;
		lret = RegSetValueEx(key, mainWndName, 0, REG_DWORD, (PBYTE)&hWnd, sizeof(hWnd));
		if (lret != ERROR_SUCCESS) {
			PVOID lpMsgBuf = GetErrorMsg(lret);
			RegAPILog.print("Set %s\\MainWindow failed:%s\n", appKeyName, lpMsgBuf);
			LocalFree(lpMsgBuf);
			RegCloseKey(key);
			ret = FALSE;
		}
		RegCloseKey(key);
		ret = TRUE;
	} else {
		PVOID lpMsgBuf = GetErrorMsg(lret);
		RegAPILog.print("Open %s\\MainWindow failed:%s\n", appKeyName, lpMsgBuf);
		LocalFree(lpMsgBuf);
		ret = FALSE;
	}
	return ret;
}

BOOL GetLogPath(char *logpath, int len)
{
	HKEY key;
	char buf[MAX_PATH];
	DWORD size = sizeof(buf);
	DWORD type;
	BOOL ret = FALSE;

	LONG lret = RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, KEY_QUERY_VALUE, &key);
	if (lret == ERROR_SUCCESS) {
		lret = RegQueryValueEx(key, logPath, NULL, &type, (PBYTE)buf, &size);
		if (lret == ERROR_SUCCESS) {
			int bufchar = ExpandEnvironmentStrings(buf, logpath, len);
			ret = (bufchar <= len);
		} else {
			//PVOID lpMsgBuf = GetErrorMsg(lret);
			//RegAPILog.print("Query %s\\MainWindow failed:%s\n", appKeyName, lpMsgBuf);
			//LocalFree(lpMsgBuf);
		}
		RegCloseKey(key);
	} else {
		//PVOID lpMsgBuf = GetErrorMsg(lret);
		//RegAPILog.print("RegOpenKeyEx %s failed:%s\n", appKeyName, lpMsgBuf);
		//LocalFree(lpMsgBuf);
	}
	return ret;
}

/////////////////////////////////////////////////////////////////////////////
// Returns the HMODULE that contains the specified memory address
static HMODULE ModuleFromAddress(PVOID pv) {
  MEMORY_BASIC_INFORMATION mbi;
  return ((VirtualQuery(pv, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
}

/////////////////////////////////////////////////////////////////////////////
//
LRESULT CALLBACK GetMsgProc(int code, WPARAM wParam, LPARAM lParam) {
  // Note: On Windows 2000, the 1st parameter to CallNextHookEx can
  // be NULL. On Windows 98, it must be the hook handle.
	MSG *pMsg;

	pMsg = (MSG *)lParam;
	//g_hWnd = pMsg->hwnd;

	// Should we create the dialog in DLLMain instead?
	// Create the RegAPIHook Window to handle the client request
	//if (g_hwndDlg == NULL) {
	//	CreateDlg();
	//}
  //if (pMsg->message == WM_MOUSEWHEEL)
  //  SendMainWndMsg(MOUSE_WHEEL_ROTATED, FALSE, NULL, 0);
	if (LOWORD(pMsg->message) == WM_LBUTTONDOWN) {
		RegAPILog.print("%s %d 0x%0X\n", __FUNCTION__, pMsg->message, pMsg->hwnd);
	}
	return CallNextHookEx(g_hhook, code, wParam, lParam);
}

/////////////////////////////////////////////////////////////////////////////
// InjectHook: Force outself to be loaded into every process
//
BOOL WINAPI InjectHook(HWND hWnd, DWORD dwThreadId) {
  BOOL fOk = FALSE;

  InjectAllProcesses();
#if 0
  if (g_hhook == NULL) {
	  RegAPILog.print("InjectHook:%X\n", hWnd);
		SetMainWnd(hWnd);
		// Save our threadID so that our GetMsgProc function can post
		// a message back to the thread when the dialog window has been created
		g_dwThreadID = GetCurrentThreadId();
		// Install the Windows' hook
		g_hhook = SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, ModuleFromAddress(GetMsgProc), dwThreadId);
		if (g_hhook != NULL) {
			if (dwThreadId)
				PostThreadMessage(dwThreadId, WM_NULL, 0, 0);
			else
				PostMessage(HWND_BROADCAST, WM_NULL, 0, 0);
		}
  }
  fOk = (g_hhook != NULL);
#endif
  return fOk;
}

BOOL WINAPI EjectHook() {
  BOOL fOk;
  DWORD err;

  if (g_hhook != NULL) {
	  RegAPILog.print("EjectHook\n");
    // Uninstall the Windows' hook
    fOk = UnhookWindowsHookEx(g_hhook);
	if (!fOk) {
      err = GetLastError();
	  RegAPILog.print("EjectHook failed:%d\n", err);
	}
	//PostMessage(HWND_BROADCAST, WM_NULL, 0, 0);
    //g_hhook = NULL;
  }
  fOk = (g_hhook == NULL);
  return fOk;
}
//

/////////////////////////////////////////////////////////////////////////////
// Send captured data to main window
BOOL SendMainWndMsg(DWORD dwType, BOOL bWideChar, PVOID pString, UINT cbSize)
{
  COPYDATASTRUCT cds;
  DWORD value;
  LPVOID lpMsgBuf;

  if (!IsWindow(g_hMainWnd)) {
		return FALSE;
  }
  switch (dwType) {
  case DLL_INJECTED:
  case DLL_EJECTED:
  case HOOK_SET_SUCCEED:
  case HOOK_SET_FAILED:
	cds.dwData = dwType;
	value = GetCurrentProcessId();
	cds.cbData = sizeof(value);
	cds.lpData = &value;
	break;
  default:
    cds.dwData = dwType;
    cds.cbData = cbSize + 1; 
    cds.lpData = (PVOID)pString;
	break;
  }
  LRESULT ret = SendMessage(g_hMainWnd, WM_COPYDATA, (WPARAM)g_hwndDlg, (LPARAM)&cds);
  RegAPILog.print("Send Message type %d, len = %d to hwnd:%X ret = %d\n", dwType, cbSize, g_hMainWnd, ret);
  if (ret != 0) {
		ret = GetLastError();
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			ret,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL );
		RegAPILog.print("Send Message type %d error: %s\n", dwType, lpMsgBuf);
	    LocalFree(lpMsgBuf);
  }
  return TRUE;
}

INT_PTR CALLBACK Dlg_Proc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  static BOOL bNotifySent = FALSE;

  switch(uMsg) {
  case WM_TIMER:
	if (!bNotifySent) {
		g_hMainWnd = GetMainWnd();
		if (g_hMainWnd) {
			SendMainWndMsg(DLL_INJECTED, FALSE, NULL, 0);
			//SendMessage(g_hMainWnd, WM_COPYDATA, 0, 0);
			bNotifySent = TRUE;
			KillTimer(hwndDlg, 1);
		}
	}
	break;
  case WM_APP + 666:
    RegAPILog.print("Get WM_APP + 666\n");
    //g_curMousePos.x = LOWORD(wParam);
    //g_curMousePos.y = HIWORD(wParam);
    //g_hHookedWnd = (HWND)lParam;
    //RegAPILog.print("Mouse at (%d, %d) hWnd %X\n", g_curMousePos.x, g_curMousePos.y, g_hHookedWnd);
	if (g_bHookLib && HookAllAPI())
		SendMainWndMsg(HOOK_SET_SUCCEED, FALSE, NULL, 0);
	else
		SendMainWndMsg(HOOK_SET_FAILED, FALSE, NULL, 0);
	break;
  case WM_APP + 777:
    RegAPILog.print("Get WM_APP + 777\n");
	CloseHookLib();
    break;
  case WM_CLOSE:
    RegAPILog.print("Get WM_CLOSE\n");
    CloseHookLib();
	RegAPILog.close();
    DestroyWindow(hwndDlg);
    break;
  default:
    return FALSE;
  }
  return TRUE;
}

UINT GetWndType(HWND hWnd)
{
  UINT nWndType = 0;
  char className[MAX_PATH];
  int classNameLen = GetClassNameA(hWnd, className, MAX_PATH);
  className[classNameLen] = '\0';
  if (lstrcmpiA(className, "RichEdit20A") == 0)
    nWndType = 3;
  else if (lstrcmpiA(className, "RichEdit20W") == 0)
    nWndType = 4;
  return nWndType;
}

/////////////////////////////////////////////////////////////////////////////
// 
BOOL APIENTRY DllMain(HINSTANCE hModule, 
                      DWORD  ul_reason_for_call, 
                      LPVOID lpReserved)
{
  HKEY key;
  DWORD initValue = 0;
  LONG lret;

  switch( ul_reason_for_call ) {
  case DLL_PROCESS_ATTACH:
	  if (GetLogPath(g_logPath, sizeof(g_logPath))) {
		RegAPILog.open(g_logPath);
		//RegAPILog.setbuffering(0);
	  }

    g_hModule = hModule;

	RegAPILog.print("DLL_PROCESS_ATTACH \"%s\"\n", GetCommandLine());
	
	// We disable thread notifications
	// Prevent the system from calling DllMain
	// when threads are created or destroyed.
	//DisableThreadLibraryCalls((HMODULE)hModule);

    // Get the hWnd of the main window (Capture Word)
	// hWnd is now passed through InjectHook
    //if (g_hMainWnd == NULL) g_hMainWnd = FindWindow(NULL, mainWndTitle);
	lret = RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, KEY_READ, &key);
	if (lret != ERROR_SUCCESS) {
		RegAPILog.print("RegOpenKeyEx %s failed:%s\n", appKeyName, GetErrorMsg(lret));
		LONG lret = RegCreateKeyEx(HKEY_CURRENT_USER, appKeyName, 0, NULL, 0, NULL, NULL, &key, NULL);
		if (lret != ERROR_SUCCESS)
			RegAPILog.print("RegCreateKeyEx %s failed:%s\n", appKeyName, GetErrorMsg(lret));
	}
	RegCloseKey(key);

	//CreateDlg();
	// Restrict to create dialog for one process only
	// Doing so in some process (probably explorer.exe) seem to cause hang
	//if (NeedHookAPI()) {
		g_procAttached = process_attach();
		if (!g_procAttached)
			RegAPILog.print("process_attach failed\n");
		g_bHookLib = OpenHookLib(hModule, &RegAPILog);
		if (g_bHookLib)
			HookAllAPI();
	//}
    break; 

  case DLL_THREAD_ATTACH:
	//RegAPILog.print("DLL_THREAD_ATTACH\n");
	if (g_procAttached) {
  		if (!thread_attach())
			RegAPILog.print("thread_attach failed\n");
	}
	break;

  case DLL_THREAD_DETACH:
	//RegAPILog.print("DLL_THREAD_DETACH\n");
	if (g_procAttached)
		thread_detach();
	break;

  case DLL_PROCESS_DETACH:
	RegAPILog.print("DLL_PROCESS_DETACH\n");
    CloseHookLib();
	RegAPILog.close();

    g_bHooked = FALSE;
    if (g_hwndDlg && IsWindow(g_hwndDlg))
      SendMessage(g_hwndDlg, WM_CLOSE, 0, 0);
    EjectHook();

	if (g_procAttached)
		process_detach();
    break;
  }
  return TRUE;
}
