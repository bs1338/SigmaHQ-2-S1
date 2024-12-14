# file_event_win_net_cli_artefact

## Title
Suspicious DotNET CLR Usage Log Artifact

## ID
e0b06658-7d1d-4cd3-bf15-03467507ff7c

## Author
frack113, omkar72, oscd.community, Wojciech Lesicki

## Date
2022-11-18

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the creation of Usage Log files by the CLR (clr.dll). These files are named after the executing process once the assembly is finished executing for the first time in the (user) session context.

## References
https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/
https://github.com/olafhartong/sysmon-modular/blob/fa1ae53132403d262be2bbd7f17ceea7e15e8c78/11_file_create/include_dotnet.xml
https://web.archive.org/web/20221026202428/https://gist.github.com/code-scrap/d7f152ffcdb3e0b02f7f394f5187f008
https://web.archive.org/web/20230329154538/https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html

## False Positives
Rundll32.exe with zzzzInvokeManagedCustomActionOutOfProc in command line and msiexec.exe as parent process - https://twitter.com/SBousseaden/status/1388064061087260675

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\UsageLogs\cmstp.exe.log" OR TgtFilePath endswithCIS "\UsageLogs\cscript.exe.log" OR TgtFilePath endswithCIS "\UsageLogs\mshta.exe.log" OR TgtFilePath endswithCIS "\UsageLogs\msxsl.exe.log" OR TgtFilePath endswithCIS "\UsageLogs\regsvr32.exe.log" OR TgtFilePath endswithCIS "\UsageLogs\rundll32.exe.log" OR TgtFilePath endswithCIS "\UsageLogs\svchost.exe.log" OR TgtFilePath endswithCIS "\UsageLogs\wscript.exe.log" OR TgtFilePath endswithCIS "\UsageLogs\wmic.exe.log") AND (NOT ((SrcProcCmdLine containsCIS "Temp" AND SrcProcCmdLine containsCIS "zzzzInvokeManagedCustomActionOutOfProc") AND SrcProcImagePath endswithCIS "\rundll32.exe" AND SrcProcParentCmdline containsCIS " -Embedding" AND SrcProcParentImagePath endswithCIS "\MsiExec.exe"))))

```