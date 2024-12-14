# proc_creation_win_python_adidnsdump

## Title
PUA - Adidnsdump Execution

## ID
26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160

## Author
frack113

## Date
2022-01-01

## Tags
attack.discovery, attack.t1018

## Description
This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks Python 3 and python.exe must be installed,
 Usee to Query/modify DNS records for Active Directory integrated DNS via LDAP


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md#atomic-test-9---remote-system-discovery---adidnsdump

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "adidnsdump" AND TgtProcImagePath endswithCIS "\python.exe"))

```