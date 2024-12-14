# proc_creation_win_keyscrambler_susp_child_process

## Title
Potentially Suspicious Child Process of KeyScrambler.exe

## ID
ca5583e9-8f80-46ac-ab91-7f314d13b984

## Author
Swachchhanda Shrawan Poudel

## Date
2024-05-13

## Tags
attack.execution, attack.defense-evasion, attack.privilege-escalation, attack.t1203, attack.t1574.002

## Description
Detects potentially suspicious child processes of KeyScrambler.exe

## References
https://twitter.com/DTCERT/status/1712785421845790799

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\KeyScrambler.exe"))

```