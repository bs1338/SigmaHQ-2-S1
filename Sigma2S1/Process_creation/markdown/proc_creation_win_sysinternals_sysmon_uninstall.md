# proc_creation_win_sysinternals_sysmon_uninstall

## Title
Uninstall Sysinternals Sysmon

## ID
6a5f68d1-c4b5-46b9-94ee-5324892ea939

## Author
frack113

## Date
2022-01-12

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects the removal of Sysmon, which could be a potential attempt at defense evasion

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md#atomic-test-11---uninstall-sysmon

## False Positives
Legitimate administrators might use this command to remove Sysmon for debugging purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-u" OR TgtProcCmdLine containsCIS "/u" OR TgtProcCmdLine containsCIS "â€“u" OR TgtProcCmdLine containsCIS "â€”u" OR TgtProcCmdLine containsCIS "â€•u") AND ((TgtProcImagePath endswithCIS "\Sysmon64.exe" OR TgtProcImagePath endswithCIS "\Sysmon.exe") OR TgtProcDisplayName = "System activity monitor")))

```