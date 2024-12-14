# registry_set_bypass_uac_using_eventviewer

## Title
Bypass UAC Using Event Viewer

## ID
674202d0-b22a-4af4-ae5f-2eda1f3da1af

## Author
frack113

## Date
2022-01-05

## Tags
attack.persistence, attack.t1547.010

## Description
Bypasses User Account Control using Event Viewer and a relevant Windows Registry modification

## References
https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md#atomic-test-1---bypass-uac-using-event-viewer-cmd

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "_Classes\mscfile\shell\open\command\(Default)" AND (NOT RegistryValue startswithCIS "%SystemRoot%\system32\mmc.exe \"%1\" %")))

```