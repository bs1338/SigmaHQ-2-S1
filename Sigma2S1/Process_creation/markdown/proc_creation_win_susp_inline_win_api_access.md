# proc_creation_win_susp_inline_win_api_access

## Title
Potential WinAPI Calls Via CommandLine

## ID
ba3f5c1b-6272-4119-9dbd-0bc8d21c2702

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-06

## Tags
attack.execution, attack.t1106

## Description
Detects the use of WinAPI Functions via the commandline. As seen used by threat actors via the tool winapiexec

## References
https://twitter.com/m417z/status/1566674631788007425

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "AddSecurityPackage" OR TgtProcCmdLine containsCIS "AdjustTokenPrivileges" OR TgtProcCmdLine containsCIS "Advapi32" OR TgtProcCmdLine containsCIS "CloseHandle" OR TgtProcCmdLine containsCIS "CreateProcessWithToken" OR TgtProcCmdLine containsCIS "CreatePseudoConsole" OR TgtProcCmdLine containsCIS "CreateRemoteThread" OR TgtProcCmdLine containsCIS "CreateThread" OR TgtProcCmdLine containsCIS "CreateUserThread" OR TgtProcCmdLine containsCIS "DangerousGetHandle" OR TgtProcCmdLine containsCIS "DuplicateTokenEx" OR TgtProcCmdLine containsCIS "EnumerateSecurityPackages" OR TgtProcCmdLine containsCIS "FreeHGlobal" OR TgtProcCmdLine containsCIS "FreeLibrary" OR TgtProcCmdLine containsCIS "GetDelegateForFunctionPointer" OR TgtProcCmdLine containsCIS "GetLogonSessionData" OR TgtProcCmdLine containsCIS "GetModuleHandle" OR TgtProcCmdLine containsCIS "GetProcAddress" OR TgtProcCmdLine containsCIS "GetProcessHandle" OR TgtProcCmdLine containsCIS "GetTokenInformation" OR TgtProcCmdLine containsCIS "ImpersonateLoggedOnUser" OR TgtProcCmdLine containsCIS "kernel32" OR TgtProcCmdLine containsCIS "LoadLibrary" OR TgtProcCmdLine containsCIS "memcpy" OR TgtProcCmdLine containsCIS "MiniDumpWriteDump" OR TgtProcCmdLine containsCIS "ntdll" OR TgtProcCmdLine containsCIS "OpenDesktop" OR TgtProcCmdLine containsCIS "OpenProcess" OR TgtProcCmdLine containsCIS "OpenProcessToken" OR TgtProcCmdLine containsCIS "OpenThreadToken" OR TgtProcCmdLine containsCIS "OpenWindowStation" OR TgtProcCmdLine containsCIS "PtrToString" OR TgtProcCmdLine containsCIS "QueueUserApc" OR TgtProcCmdLine containsCIS "ReadProcessMemory" OR TgtProcCmdLine containsCIS "RevertToSelf" OR TgtProcCmdLine containsCIS "RtlCreateUserThread" OR TgtProcCmdLine containsCIS "secur32" OR TgtProcCmdLine containsCIS "SetThreadToken" OR TgtProcCmdLine containsCIS "VirtualAlloc" OR TgtProcCmdLine containsCIS "VirtualFree" OR TgtProcCmdLine containsCIS "VirtualProtect" OR TgtProcCmdLine containsCIS "WaitForSingleObject" OR TgtProcCmdLine containsCIS "WriteInt32" OR TgtProcCmdLine containsCIS "WriteProcessMemory" OR TgtProcCmdLine containsCIS "ZeroFreeGlobalAllocUnicode") AND (NOT (TgtProcCmdLine containsCIS "GetLoadLibraryWAddress32" AND TgtProcImagePath endswithCIS "\MpCmdRun.exe"))))

```