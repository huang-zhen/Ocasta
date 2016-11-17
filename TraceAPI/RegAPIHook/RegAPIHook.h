// RegAPIHook.h
// By James Huang
// Nov.18, 2002
// Nov.8, 2011
//
// Value of dwData of COPYDATA indicates the message type
enum MSG_TYPE {
  CAPTURED_TEXT = 1,
  CAPTURED_TEXTEX = 2,
  DLL_INJECTED = 100,
  DLL_EJECTED = 101,
  HOOK_SET_SUCCEED = 200,
  HOOK_SET_FAILED = 201,
  MOUSE_WHEEL_ROTATED = 202
};
//const char HookSetEventName[] = "HookSetEvent";
// Export functions
extern "C" __declspec(dllexport) BOOL __stdcall InjectHook(HWND, DWORD);
extern "C" __declspec(dllexport) BOOL __stdcall EjectHook();

