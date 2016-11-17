@echo off
rem uninstall TraceAPI
del /f "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\TraceAPI.lnk"
del /f "%USERPROFILE%\TraceAPI\TraceAPI.exe"
del /f "%USERPROFILE%\TraceAPI\RegAPIHook.DLL"
