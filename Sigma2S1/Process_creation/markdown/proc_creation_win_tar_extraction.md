# proc_creation_win_tar_extraction

## Title
Compressed File Extraction Via Tar.EXE

## ID
bf361876-6620-407a-812f-bfe11e51e924

## Author
AdmU3

## Date
2023-12-19

## Tags
attack.collection, attack.exfiltration, attack.t1560, attack.t1560.001

## Description
Detects execution of "tar.exe" in order to extract compressed file.
 Adversaries may abuse various utilities in order to decompress data to avoid detection.


## References
https://unit42.paloaltonetworks.com/chromeloader-malware/
https://lolbas-project.github.io/lolbas/Binaries/Tar/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage

## False Positives
Likely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "-x" AND TgtProcImagePath endswithCIS "\tar.exe"))

```