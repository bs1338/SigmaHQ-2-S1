# proc_creation_win_regedit_export_critical_keys

## Title
Exports Critical Registry Keys To a File

## ID
82880171-b475-4201-b811-e9c826cd5eaa

## Author
Oddvar Moe, Sander Wiebing, oscd.community

## Date
2020-10-12

## Tags
attack.exfiltration, attack.t1012

## Description
Detects the export of a crital Registry key to a file.

## References
https://lolbas-project.github.io/lolbas/Binaries/Regedit/
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f

## False Positives
Dumping hives for legitimate purpouse i.e. backup or forensic investigation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -E " OR TgtProcCmdLine containsCIS " /E " OR TgtProcCmdLine containsCIS " â€“E " OR TgtProcCmdLine containsCIS " â€”E " OR TgtProcCmdLine containsCIS " â€•E ") AND (TgtProcCmdLine containsCIS "hklm" OR TgtProcCmdLine containsCIS "hkey_local_machine") AND (TgtProcCmdLine endswithCIS "\system" OR TgtProcCmdLine endswithCIS "\sam" OR TgtProcCmdLine endswithCIS "\security") AND TgtProcImagePath endswithCIS "\regedit.exe"))

```