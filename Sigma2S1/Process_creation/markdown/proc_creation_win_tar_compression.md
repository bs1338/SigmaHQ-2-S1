# proc_creation_win_tar_compression

## Title
Compressed File Creation Via Tar.EXE

## ID
418a3163-3247-4b7b-9933-dcfcb7c52ea9

## Author
Nasreddine Bencherchali (Nextron Systems), AdmU3

## Date
2023-12-19

## Tags
attack.collection, attack.exfiltration, attack.t1560, attack.t1560.001

## Description
Detects execution of "tar.exe" in order to create a compressed file.
 Adversaries may abuse various utilities to compress or encrypt data before exfiltration.


## References
https://unit42.paloaltonetworks.com/chromeloader-malware/
https://lolbas-project.github.io/lolbas/Binaries/Tar/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage

## False Positives
Likely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-c" OR TgtProcCmdLine containsCIS "-r" OR TgtProcCmdLine containsCIS "-u") AND TgtProcImagePath endswithCIS "\tar.exe"))

```