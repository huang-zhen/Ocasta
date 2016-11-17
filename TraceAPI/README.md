# TraceAPI
TraceAPI is a tool that intercepts Windows API calls, particularly registry calls, and logs all changes made by user applications to the Windows registry. 

It consists of a dynamic shared library RegAPIHook.dll, which is the core mechanism that intercepts Windows registry API calls, and a standalone executable TraceAPI.exe, which is used by an user to activate/deactivate the interceptions. 

Both the shared library and the executables can be built via Visual Studio with the solution file in the TraceAPI directory. After building the project, the generated TraceAPI.exe and RegAPIHook.dll can be copied into the setup directory, which can then be used as an installation package to install/uninstall TraceAPI onto a computer.

TraceAPI has been used to collect changes made by applications such as MS Word and Internet Explorer to Windows registry from multiple desktop computers for a period of a couple of months for the publication of "Ocasta: Clustering Configuration Settings for Error Recovery" in the proceedings of the 44th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN2014).
