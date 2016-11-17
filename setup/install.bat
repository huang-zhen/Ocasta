@echo off
rem install TraceAPI
mkdir "%USERPROFILE%\TraceAPI"
mkdir "%USERPROFILE%\TraceAPI\data"
copy TraceAPI.exe "%USERPROFILE%\TraceAPI"
if exist TraceAPI.map copy TraceAPI.map "%USERPROFILE%\TraceAPI"
copy RegAPIHook.DLL "%USERPROFILE%\TraceAPI"
if exist RegAPIHook.map copy RegAPIHook.map "%USERPROFILE%\TraceAPI"
copy setup.vbs "%USERPROFILE%\TraceAPI"
copy uninstall.bat "%USERPROFILE%\TraceAPI"
setup.reg
cscript "%USERPROFILE%\TraceAPI\setup.vbs"
load "%USERPROFILE%\TraceAPI\TraceAPI.exe"

