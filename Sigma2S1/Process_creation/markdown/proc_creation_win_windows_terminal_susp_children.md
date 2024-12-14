# proc_creation_win_windows_terminal_susp_children

## Title
Suspicious WindowsTerminal Child Processes

## ID
8de89e52-f6e1-4b5b-afd1-41ecfa300d48

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-25

## Tags
attack.execution, attack.persistence

## Description
Detects suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal (see references section)

## References
https://persistence-info.github.io/Data/windowsterminalprofile.html
https://twitter.com/nas_bench/status/1550836225652686848

## False Positives
Other legitimate "Windows Terminal" profiles

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((SrcProcImagePath endswithCIS "\WindowsTerminal.exe" OR SrcProcImagePath endswithCIS "\wt.exe") AND ((TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\csc.exe") OR (TgtProcImagePath containsCIS "C:\Users\Public\" OR TgtProcImagePath containsCIS "\Downloads\" OR TgtProcImagePath containsCIS "\Desktop\" OR TgtProcImagePath containsCIS "\AppData\Local\Temp\" OR TgtProcImagePath containsCIS "\Windows\TEMP\") OR (TgtProcCmdLine containsCIS " iex " OR TgtProcCmdLine containsCIS " icm" OR TgtProcCmdLine containsCIS "Invoke-" OR TgtProcCmdLine containsCIS "Import-Module " OR TgtProcCmdLine containsCIS "ipmo " OR TgtProcCmdLine containsCIS "DownloadString(" OR TgtProcCmdLine containsCIS " /c " OR TgtProcCmdLine containsCIS " /k " OR TgtProcCmdLine containsCIS " /r "))) AND (NOT ((TgtProcCmdLine containsCIS "Import-Module" AND TgtProcCmdLine containsCIS "Microsoft.VisualStudio.DevShell.dll" AND TgtProcCmdLine containsCIS "Enter-VsDevShell") OR (TgtProcCmdLine containsCIS "\AppData\Local\Packages\Microsoft.WindowsTerminal_" AND TgtProcCmdLine containsCIS "\LocalState\settings.json") OR (TgtProcCmdLine containsCIS "C:\Program Files\Microsoft Visual Studio\" AND TgtProcCmdLine containsCIS "\Common7\Tools\VsDevCmd.bat")))))

```