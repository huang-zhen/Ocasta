set WshShell = WScript.CreateObject("WScript.Shell")
Set WshSysEnv = WshShell.Environment("PROCESS")
strDesktop = WshShell.SpecialFolders("Desktop")
strStartup = WshShell.SpecialFolders("Startup")
strWorkDir = WshSysEnv("USERPROFILE") + "\TraceAPI"
set oShellLink = WshShell.CreateShortcut(strStartup & "\TraceAPI.lnk")
oShellLink.TargetPath = strWorkDir + "\TraceAPI.exe"
oShellLink.WindowStyle = 1
oShellLink.Description = "TraceAPI"
oShellLink.WorkingDirectory = strWorkDir
oShellLink.Save
