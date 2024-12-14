# proc_creation_win_hktl_empire_powershell_launch

## Title
HackTool - Empire PowerShell Launch Parameters

## ID
79f4ede3-402e-41c8-bc3e-ebbf5f162581

## Author
Florian Roth (Nextron Systems)

## Date
2019-04-20

## Tags
attack.execution, attack.t1059.001

## Description
Detects suspicious powershell command line parameters used in Empire

## References
https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165
https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191
https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178
https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64

## False Positives
Other tools that incidentally use the same command line parameters

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -NoP -sta -NonI -W Hidden -Enc " OR TgtProcCmdLine containsCIS " -noP -sta -w 1 -enc " OR TgtProcCmdLine containsCIS " -NoP -NonI -W Hidden -enc " OR TgtProcCmdLine containsCIS " -noP -sta -w 1 -enc" OR TgtProcCmdLine containsCIS " -enc  SQB" OR TgtProcCmdLine containsCIS " -nop -exec bypass -EncodedCommand "))

```