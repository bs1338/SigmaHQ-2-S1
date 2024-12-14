# proc_creation_win_dll_sideload_vmware_xfer

## Title
DLL Sideloading by VMware Xfer Utility

## ID
ebea773c-a8f1-42ad-a856-00cb221966e8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-02

## Tags
attack.defense-evasion, attack.t1574.002

## Description
Detects execution of VMware Xfer utility (VMwareXferlogs.exe) from the non-default directory which may be an attempt to sideload arbitrary DLL

## References
https://www.sentinelone.com/labs/lockbit-ransomware-side-loads-cobalt-strike-beacon-with-legitimate-vmware-utility/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\VMwareXferlogs.exe" AND (NOT TgtProcImagePath startswithCIS "C:\Program Files\VMware\")))

```