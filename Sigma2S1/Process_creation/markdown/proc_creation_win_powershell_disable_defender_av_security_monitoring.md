# proc_creation_win_powershell_disable_defender_av_security_monitoring

## Title
Disable Windows Defender AV Security Monitoring

## ID
a7ee1722-c3c5-aeff-3212-c777e4733217

## Author
ok @securonix invrep-de, oscd.community, frack113

## Date
2020-10-12

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects attackers attempting to disable Windows Defender using Powershell

## References
https://research.nccgroup.com/2020/06/23/wastedlocker-a-new-ransomware-variant-developed-by-the-evil-corp-group/
https://rvsec0n.wordpress.com/2020/01/24/malwares-that-bypass-windows-defender/
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md

## False Positives
Minimal, for some older versions of dev tools, such as pycharm, developers were known to sometimes disable Windows Defender to improve performance, but this generally is not considered a good security practice.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (TgtProcCmdLine containsCIS "-DisableBehaviorMonitoring $true" OR TgtProcCmdLine containsCIS "-DisableRuntimeMonitoring $true")) OR (TgtProcImagePath endswithCIS "\sc.exe" AND ((TgtProcCmdLine containsCIS "delete" AND TgtProcCmdLine containsCIS "WinDefend") OR (TgtProcCmdLine containsCIS "config" AND TgtProcCmdLine containsCIS "WinDefend" AND TgtProcCmdLine containsCIS "start=disabled") OR (TgtProcCmdLine containsCIS "stop" AND TgtProcCmdLine containsCIS "WinDefend")))))

```