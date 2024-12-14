# proc_creation_win_hktl_redmimicry_winnti_playbook

## Title
HackTool - RedMimicry Winnti Playbook Execution

## ID
95022b85-ff2a-49fa-939a-d7b8f56eeb9b

## Author
Alexander Rausch

## Date
2020-06-24

## Tags
attack.execution, attack.defense-evasion, attack.t1106, attack.t1059.003, attack.t1218.011

## Description
Detects actions caused by the RedMimicry Winnti playbook a automated breach emulations utility

## References
https://redmimicry.com/posts/redmimicry-winnti/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "gthread-3.6.dll" OR TgtProcCmdLine containsCIS "\Windows\Temp\tmp.bat" OR TgtProcCmdLine containsCIS "sigcmm-2.4.dll") AND (TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\cmd.exe")))

```