# proc_creation_win_explorer_nouaccheck

## Title
Explorer NOUACCHECK Flag

## ID
534f2ef7-e8a2-4433-816d-c91bccde289b

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-23

## Tags
attack.defense-evasion, attack.t1548.002

## Description
Detects suspicious starts of explorer.exe that use the /NOUACCHECK flag that allows to run all sub processes of that newly started explorer.exe without any UAC checks

## References
https://twitter.com/ORCA6665/status/1496478087244095491

## False Positives
Domain Controller User Logon
Unknown how many legitimate software products use that method

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/NOUACCHECK" AND TgtProcImagePath endswithCIS "\explorer.exe") AND (NOT (SrcProcCmdLine = "C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule" OR SrcProcImagePath = "C:\Windows\System32\svchost.exe"))))

```