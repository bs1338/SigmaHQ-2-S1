# proc_creation_win_reg_enumeration_for_credentials_in_registry

## Title
Enumeration for Credentials in Registry

## ID
e0b0c2ab-3d52-46d9-8cb7-049dc775fbd1

## Author
frack113

## Date
2021-12-20

## Tags
attack.credential-access, attack.t1552.002

## Description
Adversaries may search the Registry on compromised systems for insecurely stored credentials.
The Windows Registry stores configuration information that can be used by the system or other programs.
Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.002/T1552.002.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " query " AND TgtProcCmdLine containsCIS "/t " AND TgtProcCmdLine containsCIS "REG_SZ" AND TgtProcCmdLine containsCIS "/s") AND TgtProcImagePath endswithCIS "\reg.exe") AND ((TgtProcCmdLine containsCIS "/f " AND TgtProcCmdLine containsCIS "HKLM") OR (TgtProcCmdLine containsCIS "/f " AND TgtProcCmdLine containsCIS "HKCU") OR TgtProcCmdLine containsCIS "HKCU\Software\SimonTatham\PuTTY\Sessions")))

```