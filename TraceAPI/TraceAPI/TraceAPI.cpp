/*
 * Copyright (C) 2016 Zhen Huang
 */
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <tchar.h>

#include <set>
#include <assert.h>
#include "res\resource.h"
#include "..\RegAPIHOOK\RegAPIHOOK.h"
#include "..\RegAPIHOOK\CLogRegAPIEntry.h"
using namespace std;

// Enable SELF_TEST when debugging TraceAPI with Visual Studio, otherwise system will hang 
// and have to log off the user to recover
#define SELF_TEST

static HWND     g_hWnd;
static HMODULE hDLLModule = NULL;
static TCHAR g_dllpath[MAX_PATH];

//#define DO_EJECTDLL
#define EJECTDLL_MESSAGE

#ifdef DO_EJECTDLL
#ifdef EJECTDLL_MESSAGE
static set<HWND> g_procHwnds;
#else
static set<DWORD> g_procIds;
#endif
#endif

#define TASKBARICONID 1
#define USR_NOTIFYICON (WM_USER + 1)
#define WM_MY_PING (WM_USER + 999)
#define SESAME 0xDEADBEEF

static const TCHAR appKeyName[] = TEXT("Software\\Sunbird\\TraceAPI");
static const TCHAR APIDLLName[] = TEXT("APIDLL");
static const TCHAR mainWndName[] = TEXT("MainWindow");

typedef BOOL (WINAPI* LPFNDLLFUNC1)(HWND, DWORD);
typedef BOOL (WINAPI* LPFNDLLFUNC2)();
LPFNDLLFUNC1 InjectHookFn;
LPFNDLLFUNC2 EjectHookFn;

BOOL GetAPIDLLPath(LPTSTR dllpath, DWORD len)
{
#ifndef SELF_TEST
	BOOL ret = FALSE;
	HKEY key;
	TCHAR buf[MAX_PATH];
	DWORD valuelen = sizeof(buf)/sizeof(TCHAR);
	DWORD type;

	LONG lret = RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, KEY_QUERY_VALUE, &key);
	if (lret == ERROR_SUCCESS) {
		lret = RegQueryValueEx(key, APIDLLName, 0, &type, (PBYTE)buf, &valuelen);
		if (lret == ERROR_SUCCESS) {
			int bufchar = ExpandEnvironmentStrings(buf, dllpath, len);
			ret = TRUE;
		}
		RegCloseKey(key);
	}
	return ret;
#else
#ifdef _DEBUG
	_tcsncpy(dllpath, TEXT("..\\RegAPIHook\\Debug\\RegAPIHook.dll"), len);
#else
	_tcsncpy(dllpath, TEXT("..\\RegAPIHook\\Release\\RegAPIHook.dll"), len);
#endif
	return TRUE;
#endif
}

BOOL SetMainWnd(HWND hWnd)
{
	BOOL ret;
	HKEY key;
	TCHAR buf[80];

	LONG lret = RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, KEY_SET_VALUE, &key);
	if (lret == ERROR_SUCCESS) {
		lret = RegSetValueEx(key, mainWndName, 0, REG_DWORD, (PBYTE)&hWnd, sizeof(hWnd));
		if (lret != ERROR_SUCCESS) {
			//PVOID lpMsgBuf = GetErrorMsg(lret);
			//RegAPILog.print("Set %s\\MainWindow failed:%s\n", appKeyName, lpMsgBuf);
			//LocalFree(lpMsgBuf);
			RegCloseKey(key);
			ret = FALSE;
		}
		RegCloseKey(key);
		_sntprintf(buf, sizeof(buf)/sizeof(TCHAR), TEXT("SetMainWnd:%X\n"), (unsigned int)hWnd);
		//OutputDebugString(buf);
		ret = TRUE;
	} else {
		//PVOID lpMsgBuf = GetErrorMsg(lret);
		//RegAPILog.print("Open %s\\MainWindow failed:%s\n", appKeyName, lpMsgBuf);
		//LocalFree(lpMsgBuf);
		ret = FALSE;
	}
	return ret;
}

#ifdef DO_EJECTDLL
#ifdef EJECTDLL_MESSAGE
BOOL EjectDLL(HWND hwnd)
{
	SendMessage(hwnd, WM_CLOSE, NULL, NULL);
	return TRUE;
}
#else
BOOL EjectDLL(DWORD processId, const char *libPath)
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE; 
  MODULEENTRY32 me32; 
  BOOL bFound = FALSE;
 
  assert (processId != GetCurrentProcessId());

//  Take a snapshot of all modules in the specified process. 
  hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, processId); 
  if( hModuleSnap == INVALID_HANDLE_VALUE ) 
  { 
    return( FALSE ); 
  } 
 
//  Set the size of the structure before using it. 
  me32.dwSize = sizeof( MODULEENTRY32 ); 
 
//  Retrieve information about the first module, 
//  and exit if unsuccessful 
  if( !Module32First( hModuleSnap, &me32 ) ) 
  { 
    CloseHandle( hModuleSnap );     // Must clean up the snapshot object! 
    return( FALSE ); 
  } 

  do {
	  if (strcmp(me32.szModule, libPath) == 0 || strcmp(me32.szExePath, libPath) == 0) {
		  bFound = TRUE;
		  break;
	  }
    //printf( "\n     base address   = 0x%08X", (DWORD) me32.modBaseAddr ); 
    //printf( "\n     base size      = %d",             me32.modBaseSize ); 
  } while( Module32Next( hModuleSnap, &me32 ) ); 
 
if (bFound) {
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION, FALSE, processId);
	if (hProcess != INVALID_HANDLE_VALUE) {
		char buf[80];

		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary"), (LPVOID)me32.modBaseAddr, 0, NULL);
		if (hThread != INVALID_HANDLE_VALUE) {
			_sntprintf(buf, sizeof(buf), TEXT("EjectDLL created thread in %d\n"), processId);
			OutputDebugString(buf);
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		} else {
			_sntprintf(buf, sizeof(buf), TEXT("EjectDLL failed to create thread in %d(%d)\n"), processId, GetLastError());
			OutputDebugString(buf);
		}
		CloseHandle(hProcess);
	}
}
//  Do not forget to clean up the snapshot object. 
  CloseHandle( hModuleSnap ); 
  return( TRUE ); 
} 
#endif
#endif

BOOL FindPrevInstance()
{
	BOOL found = FALSE;
	HWND hwnd = FindWindow(TEXT("TraceAPIClass"), TEXT("TraceAPI"));
	if (hwnd) {
		found = (SendMessage(hwnd, WM_MY_PING, NULL, NULL) == SESAME);
	}
	return found;
}

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY WinMain(
	HINSTANCE hInstance, 
	HINSTANCE hPrevInstance,
    LPSTR     lpszCmdLine, 
	int       nCmdShow
	)
{
    HWND     hwnd;
    MSG      msg ;
    WNDCLASS wndclass ;
	HKEY	key;

	if (FindPrevInstance())
		return 0;

    if (RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, NULL, &key) != ERROR_SUCCESS)
		RegCreateKey(HKEY_CURRENT_USER, appKeyName, &key);
	RegCloseKey(key);

	if (GetAPIDLLPath(g_dllpath, sizeof(g_dllpath))) {
		hDLLModule = LoadLibrary(g_dllpath);
		if (hDLLModule == NULL) {
			MessageBox(NULL, g_dllpath, TEXT("Unable to load DLL"), MB_OK);
			return 0;
		}
	} else {
		MessageBox(NULL, TEXT("Unable to load DLL"), TEXT("TraceAPI"), MB_OK);
		return 0;
	}

	if(!hPrevInstance) 
	{
		wndclass.style         = CS_HREDRAW | CS_VREDRAW ;
		wndclass.lpfnWndProc   = WndProc ;
		wndclass.cbClsExtra    = 0 ;
		wndclass.cbWndExtra    = 0 ;
		wndclass.hInstance     = hInstance ;
		wndclass.hIcon         = LoadIcon(NULL, IDI_APPLICATION) ;
		wndclass.hCursor       = LoadCursor(NULL, IDC_ARROW) ;
		wndclass.hbrBackground =(HBRUSH) GetStockObject(WHITE_BRUSH) ;
		wndclass.lpszMenuName  = NULL;
		wndclass.lpszClassName = TEXT("TraceAPIClass");
		RegisterClass(&wndclass) ;
	}

	hwnd = ::CreateWindow(
		TEXT("TraceAPIClass"),		// LPCTSTR lpClassName
		TEXT("TraceAPI"),				// LPCTSTR lpWindowName
   		WS_OVERLAPPEDWINDOW,	// DWORD dwStyle
		0,						// int x
		0,						// int y 
		320,					// int nWidth
		200,					// int nHeight
		NULL,					// HWND hWndParent
		NULL,					// HMENU hMenu
		hInstance,				// HANDLE hInstance
		NULL                    // PVOID lpParam 
		);				
	g_hWnd = hwnd;

  /* Load DLL into other processes */
  if (hDLLModule) {
	InjectHookFn = (LPFNDLLFUNC1)GetProcAddress(hDLLModule, "_InjectHook@8");
	if (InjectHookFn) {
#ifdef SELF_TEST
		InjectHookFn(hwnd, GetCurrentThreadId());
#else
		InjectHookFn(hwnd, 0);
#endif
	} else
		MessageBox(hwnd, TEXT("Unable to locate InjectHook function"), TEXT("ERROR"), MB_OK);
  }

	::ShowWindow(hwnd, SW_HIDE) ;
	::UpdateWindow(hwnd) ;
	
	SetMainWnd(hwnd);

	SetTimer(hwnd, 1, 10, NULL);
	while(::GetMessage(&msg, NULL, 0, 0))
	{
		::TranslateMessage(&msg) ;
		::DispatchMessage(&msg) ;
	}

#ifndef SELF_TEST	
	EjectHookFn = (LPFNDLLFUNC2)GetProcAddress(hDLLModule, "_EjectHook@0");
	if (EjectHookFn)
		EjectHookFn();
#endif

	if (hDLLModule)
		FreeLibrary(hDLLModule);

	SetMainWnd(NULL);
	return (int)msg.wParam ;
}

VOID APIENTRY DisplayContextMenu(HWND hwnd, int id, POINT pt) 
{ 
    HMENU hmenu;            // top-level menu 
    HMENU hmenuTrackPopup;  // shortcut menu 
 
    // Load the menu resource. 
 
    if ((hmenu = LoadMenu(GetModuleHandle(NULL), (LPCTSTR)MAKEINTRESOURCE(IDR_POPUP))) == NULL)
        return; 
 
    // TrackPopupMenu cannot display the menu bar so get 
    // a handle to the first shortcut menu. 
 
    hmenuTrackPopup = GetSubMenu(hmenu, 0); 
 
    // Display the shortcut menu. Track the right mouse 
    // button. 
 
    TrackPopupMenu(hmenuTrackPopup, 
            TPM_LEFTALIGN | TPM_RIGHTBUTTON, 
            pt.x, pt.y, 0, hwnd, NULL); 
 
    // Destroy the menu. 
 
    DestroyMenu(hmenu); 
} 

LRESULT CALLBACK WndProc(
	HWND   hwnd, 
	UINT   message, 
	WPARAM wParam, 
	LPARAM lParam
	)
{
	static TCHAR	pid[80];
	static TCHAR    textOutA[] = TEXT("This is from TextOutA");
	static TCHAR	dllLoaded[] = TEXT("APIDLL loaded!");
	static TCHAR	dllNotLoaded[] = TEXT("APIDLL NOT loaded!");
    static RECT rect = {0, 40, 180, 60};
    HDC hDC;                               
    PAINTSTRUCT ps;
    PCOPYDATASTRUCT pCDS;
	TCHAR buf[80], msg[80];
	static HWND hDlg = NULL;
	static BOOL bDlgHooked = FALSE;
#ifdef SELF_TEST
	HKEY key;
	DWORD len = sizeof(buf)/sizeof(TCHAR);
#endif
	
	switch(message)
    {
	case WM_CREATE: {
		// Add the icon to system tray
		NOTIFYICONDATA tnid;

		tnid.cbSize = sizeof(NOTIFYICONDATA);
		tnid.hWnd = hwnd;
		tnid.uID = TASKBARICONID;
		tnid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
		tnid.uCallbackMessage = USR_NOTIFYICON;
		tnid.hIcon = (HICON)LoadImage(GetModuleHandle(NULL),
					(LPCTSTR)MAKEINTRESOURCE(IDI_TRAYICON),
					IMAGE_ICON, 16, 16,
					LR_DEFAULTCOLOR);
		_sntprintf(tnid.szTip, sizeof(tnid.szTip)/sizeof(TCHAR), TEXT("TraceAPI"));
		Shell_NotifyIcon(NIM_ADD, &tnid);
		}
		break;
	case WM_TIMER:
		if (hDlg) {
			if (!bDlgHooked) {
				::SendMessage(hDlg, WM_APP + 666, NULL, NULL);
				bDlgHooked = TRUE;
			}
		}
#ifdef SELF_TEST
		{
			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			ZeroMemory( &si, sizeof(si) );
			si.cb = sizeof(si);
			ZeroMemory( &pi, sizeof(pi) );

			if (RegOpenKeyEx(HKEY_CURRENT_USER, appKeyName, 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
				RegQueryValueEx(key, APIDLLName, 0, NULL, (LPBYTE)&buf, &len);
				RegCloseKey(key);
			}
			//HMODULE hdll = LoadLibrary(TEXT("C:\\Program Files\\Adobe\\Reader 10.0\\Reader\\AcroRd32.dll"));
			//if (hdll)
			//	FreeLibrary(hdll);
			PTSTR cmdlines[] = {
				TEXT("cmd.exe"), 
				TEXT("C:\\Program Files\\Internet Explorer\\iexplore.exe"),
				TEXT("C:\\Program Files\\WinSCP\\WinSCP.exe"),
				TEXT("C:\\cygwin\\bin\\bash --login -i"),
				TEXT("C:\\Program Files\\Microsoft Visual Studio 8\\Common7\\IDE\\devenv.exe"),
			};
			for (int i = 0; i < sizeof(cmdlines)/sizeof(PTSTR); i++) {
				TCHAR cmdline[MAX_PATH];
				_tcscpy(cmdline, cmdlines[i]);
				if (!CreateProcess(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
					TCHAR msg[MAX_PATH];
					_stprintf(msg, TEXT("Unable to execute %s\n"), cmdline);
					MessageBox(NULL, msg, NULL, MB_OK);
				}
			}
		}
#endif
		KillTimer(hwnd, 1);
		break;
    case WM_PAINT:
        hDC = ::BeginPaint(hwnd, &ps);
#if 0
		_snprintf(pid, sizeof(pid), "PID:%d HWND:%X", GetCurrentProcessId(), hwnd);
		::TextOutA(hDC, 50, 0, pid, lstrlen(pid));
		::TextOutA(hDC, 0, 20, textOutA, lstrlen(textOutA));
    ::DrawTextA(hDC, drawTextA, lstrlen(drawTextA), &rect, DT_LEFT);
		if (hDLLModule != NULL)
			::TextOutA(hDC, 0, 80, dllLoaded, lstrlen(dllLoaded));
		else
			::TextOutA(hDC, 0, 80, dllNotLoaded, lstrlen(dllNotLoaded));
#endif
        ::EndPaint(hwnd, &ps);
		return 0;
	case WM_DESTROY: {
		NOTIFYICONDATA tnid;

		tnid.cbSize = sizeof(NOTIFYICONDATA);
		tnid.hWnd = hwnd;
		tnid.uID = TASKBARICONID;
		Shell_NotifyIcon(NIM_DELETE, &tnid);
#ifdef DO_EJECTDLL
#ifdef EJECTDLL_MESSAGE
		for (set<HWND>::iterator it = g_procHwnds.begin(); it != g_procHwnds.end(); it++) {
			if (*it != hwnd)
				EjectDLL(*it);
		}
#else
		for (set<DWORD>::iterator it = g_procIds.begin(); it != g_procIds.end(); it++) {
			if (*it != GetCurrentProcessId())
				EjectDLL(*it, g_dllpath);
		}
#endif
#endif
        ::PostQuitMessage(0);
		}
		return 0;
	case WM_COPYDATA:
		pCDS = (PCOPYDATASTRUCT) lParam;
		if (pCDS->dwData == DLL_INJECTED) {
			_sntprintf(buf, sizeof(buf)/sizeof(TCHAR),  TEXT("DLL_INJECTED"));
#ifdef DO_EJECTDLL
#ifdef EJECTDLL_MESSAGE
			if (*(DWORD*)pCDS->lpData != GetCurrentProcessId())
				g_procHwnds.insert((HWND)wParam);
#else
			g_procIds.insert(*(DWORD*)pCDS->lpData);
#endif
#endif
		}
		else if(pCDS->dwData ==	HOOK_SET_SUCCEED)
			_sntprintf(buf, sizeof(buf)/sizeof(TCHAR),  TEXT("API_HOOKED"));
		else if(pCDS->dwData ==	HOOK_SET_FAILED)
			_sntprintf(buf, sizeof(buf)/sizeof(TCHAR), TEXT("API_NOT_HOOKED"));
		_sntprintf(msg, sizeof(msg)/sizeof(TCHAR), TEXT("%s Pid:%d, hWnd:%X\n"), buf, *(DWORD*)pCDS->lpData, wParam);
		//if (hDlg == NULL)
			//hDlg = (HWND)wParam;
			//bDlgHooked = FALSE;
		//OutputDebugString(msg);
		return 0;
	case USR_NOTIFYICON: {
		UINT uID;
		UINT uMouseMsg;

		uID = (UINT)wParam;
		uMouseMsg = (UINT)lParam;

		if (uMouseMsg == WM_RBUTTONDOWN) {
			POINT pt;
			SetForegroundWindow(hwnd);
			// Retrieve the mouse position
			if (!GetCursorPos(&pt))
				pt.x = pt.y = 0;
			DisplayContextMenu(hwnd, IDR_POPUP, pt);
			PostMessage(hwnd, WM_NULL, 0, 0);
			}
		}
		return 0;
	case WM_COMMAND: {
		WORD cmd = LOWORD(wParam);
		if (cmd == ID_EXIT)
			PostMessage(hwnd, WM_DESTROY, 0, 0);
		}
		return 0;
	case WM_MY_PING:
		return SESAME;
    default:
        break;
    }
    return DefWindowProc(hwnd, message, wParam, lParam) ;
}
