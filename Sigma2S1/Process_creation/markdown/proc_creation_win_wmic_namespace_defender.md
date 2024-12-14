# proc_creation_win_wmic_namespace_defender

## Title
Potential Windows Defender Tampering Via Wmic.EXE

## ID
51cbac1e-eee3-4a90-b1b7-358efb81fa0a

## Author
frack113

## Date
2022-12-11

## Tags
attack.credential-access, attack.t1546.008

## Description
Detects potential tampering with Windows Defender settings such as adding exclusion using wmic

## References
https://github.com/redcanaryco/atomic-red-team/blob/5c1e6f1b4fafd01c8d1ece85f510160fc1275fbf/atomics/T1562.001/T1562.001.md
https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/
https://www.bleepingcomputer.com/news/security/iobit-forums-hacked-to-spread-ransomware-to-its-members/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/Namespace:\\root\Microsoft\Windows\Defender" AND TgtProcImagePath endswithCIS "\WMIC.exe"))

```