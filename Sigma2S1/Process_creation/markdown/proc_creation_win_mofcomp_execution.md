# proc_creation_win_mofcomp_execution

## Title
Potential Suspicious Mofcomp Execution

## ID
1dd05363-104e-4b4a-b963-196a534b03a1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-12

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of the "mofcomp" utility as a child of a suspicious shell or script running utility or by having a suspicious path in the commandline.
 The "mofcomp" utility parses a file containing MOF statements and adds the classes and class instances defined in the file to the WMI repository.
Attackers abuse this utility to install malicious MOF scripts


## References
https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
https://github.com/The-DFIR-Report/Sigma-Rules/blob/75260568a7ffe61b2458ca05f6f25914efb44337/win_mofcomp_execution.yml
https://learn.microsoft.com/en-us/windows/win32/wmisdk/mofcomp

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\wsl.exe" OR SrcProcImagePath endswithCIS "\wscript.exe" OR SrcProcImagePath endswithCIS "\cscript.exe") OR (TgtProcCmdLine containsCIS "\AppData\Local\Temp" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\WINDOWS\Temp\" OR TgtProcCmdLine containsCIS "%temp%" OR TgtProcCmdLine containsCIS "%tmp%" OR TgtProcCmdLine containsCIS "%appdata%")) AND TgtProcImagePath endswithCIS "\mofcomp.exe") AND (NOT (TgtProcCmdLine containsCIS "C:\Windows\TEMP\" AND TgtProcCmdLine endswithCIS ".mof" AND SrcProcImagePath = "C:\Windows\System32\wbem\WmiPrvSE.exe")) AND (NOT (TgtProcCmdLine containsCIS "C:\Windows\TEMP\" AND TgtProcCmdLine endswithCIS ".mof"))))

```