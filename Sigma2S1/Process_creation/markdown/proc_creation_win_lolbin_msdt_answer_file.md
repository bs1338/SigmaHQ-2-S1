# proc_creation_win_lolbin_msdt_answer_file

## Title
Execute MSDT Via Answer File

## ID
9c8c7000-3065-44a8-a555-79bcba5d9955

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-13

## Tags
attack.defense-evasion, attack.t1218, attack.execution

## Description
Detects execution of "msdt.exe" using an answer file which is simulating the legitimate way of calling msdt via "pcwrun.exe" (For example from the compatibility tab)

## References
https://lolbas-project.github.io/lolbas/Binaries/Msdt/

## False Positives
Possible undocumented parents of "msdt" other than "pcwrun"

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -af " OR TgtProcCmdLine containsCIS " /af ") AND (TgtProcCmdLine containsCIS "\WINDOWS\diagnostics\index\PCWDiagnostic.xml" AND TgtProcImagePath endswithCIS "\msdt.exe")) AND (NOT SrcProcImagePath endswithCIS "\pcwrun.exe")))

```