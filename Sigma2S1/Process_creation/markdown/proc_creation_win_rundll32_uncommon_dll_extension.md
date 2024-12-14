# proc_creation_win_rundll32_uncommon_dll_extension

## Title
Rundll32 Execution With Uncommon DLL Extension

## ID
c3a99af4-35a9-4668-879e-c09aeb4f2bdf

## Author
Tim Shelton, Florian Roth (Nextron Systems), Yassine Oukessou

## Date
2022-01-13

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects the execution of rundll32 with a command line that doesn't contain a common extension

## References
https://twitter.com/mrd0x/status/1481630810495139841?s=12

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\rundll32.exe" AND (NOT (TgtProcCmdLine = "" OR ((TgtProcCmdLine containsCIS ".cpl " OR TgtProcCmdLine containsCIS ".cpl," OR TgtProcCmdLine containsCIS ".cpl\"" OR TgtProcCmdLine containsCIS ".cpl'" OR TgtProcCmdLine containsCIS ".dll " OR TgtProcCmdLine containsCIS ".dll," OR TgtProcCmdLine containsCIS ".dll\"" OR TgtProcCmdLine containsCIS ".dll'" OR TgtProcCmdLine containsCIS ".inf " OR TgtProcCmdLine containsCIS ".inf," OR TgtProcCmdLine containsCIS ".inf\"" OR TgtProcCmdLine containsCIS ".inf'") OR (TgtProcCmdLine endswithCIS ".cpl" OR TgtProcCmdLine endswithCIS ".dll" OR TgtProcCmdLine endswithCIS ".inf")) OR TgtProcCmdLine containsCIS " -localserver " OR TgtProcCmdLine IS NOT EMPTY OR ((TgtProcCmdLine containsCIS ":\Windows\Installer\" AND TgtProcCmdLine containsCIS ".tmp" AND TgtProcCmdLine containsCIS "zzzzInvokeManagedCustomActionOutOfProc") AND SrcProcImagePath endswithCIS "\msiexec.exe"))) AND (NOT (SrcProcCmdLine containsCIS ":\Users\" AND SrcProcCmdLine containsCIS "\AppData\Local\Microsoft\EdgeUpdate\Install\{" AND SrcProcCmdLine containsCIS "\EDGEMITMP_" AND SrcProcCmdLine containsCIS ".tmp\setup.exe" AND SrcProcCmdLine containsCIS "--install-archive=" AND SrcProcCmdLine containsCIS "--previous-version=" AND SrcProcCmdLine containsCIS "--msedgewebview --verbose-logging --do-not-launch-msedge --user-level"))))

```