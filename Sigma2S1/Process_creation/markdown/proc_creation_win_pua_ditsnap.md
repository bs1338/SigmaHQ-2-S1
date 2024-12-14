# proc_creation_win_pua_ditsnap

## Title
PUA - DIT Snapshot Viewer

## ID
d3b70aad-097e-409c-9df2-450f80dc476b

## Author
Furkan Caliskan (@caliskanfurkan_)

## Date
2020-07-04

## Tags
attack.credential-access, attack.t1003.003

## Description
Detects the use of Ditsnap tool, an inspection tool for Active Directory database, ntds.dit.

## References
https://thedfirreport.com/2020/06/21/snatch-ransomware/
https://web.archive.org/web/20201124182207/https://github.com/yosqueoy/ditsnap

## False Positives
Legitimate admin usage

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\ditsnap.exe" OR TgtProcCmdLine containsCIS "ditsnap.exe"))

```