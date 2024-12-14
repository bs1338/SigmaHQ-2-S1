# proc_creation_win_pua_nmap_zenmap

## Title
PUA - Nmap/Zenmap Execution

## ID
f6ecd1cf-19b8-4488-97f6-00f0924991a3

## Author
frack113

## Date
2021-12-10

## Tags
attack.discovery, attack.t1046

## Description
Detects usage of namp/zenmap. Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation

## References
https://nmap.org/
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md#atomic-test-3---port-scan-nmap-for-windows

## False Positives
Legitimate administrator activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\nmap.exe" OR TgtProcImagePath endswithCIS "\zennmap.exe"))

```