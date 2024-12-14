# proc_creation_win_hktl_cobaltstrike_process_patterns

## Title
Potential CobaltStrike Process Patterns

## ID
f35c5d71-b489-4e22-a115-f003df287317

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2021-07-27

## Tags
attack.execution, attack.t1059

## Description
Detects potential process patterns related to Cobalt Strike beacon activity

## References
https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/
https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS "conhost.exe 0xffffffff -ForceV1" AND (SrcProcCmdLine containsCIS "cmd.exe /C echo" AND SrcProcCmdLine containsCIS " > \\.\pipe")) OR (TgtProcCmdLine endswithCIS "conhost.exe 0xffffffff -ForceV1" AND SrcProcCmdLine endswithCIS "/C whoami") OR (TgtProcCmdLine endswithCIS "cmd.exe /C whoami" AND SrcProcImagePath startswithCIS "C:\Temp\") OR ((TgtProcCmdLine containsCIS "cmd.exe /c echo" AND TgtProcCmdLine containsCIS "> \\.\pipe") AND (SrcProcImagePath endswithCIS "\runonce.exe" OR SrcProcImagePath endswithCIS "\dllhost.exe"))))

```