# proc_creation_win_configsecuritypolicy_download_file

## Title
Arbitrary File Download Via ConfigSecurityPolicy.EXE

## ID
1f0f6176-6482-4027-b151-00071af39d7e

## Author
frack113

## Date
2021-11-26

## Tags
attack.exfiltration, attack.t1567

## Description
Detects the execution of "ConfigSecurityPolicy.EXE", a binary part of Windows Defender used to manage settings in Windows Defender.
Users can configure different pilot collections for each of the co-management workloads.
It can be abused by attackers in order to upload or download files.


## References
https://lolbas-project.github.io/lolbas/Binaries/ConfigSecurityPolicy/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "ConfigSecurityPolicy.exe" OR TgtProcImagePath endswithCIS "\ConfigSecurityPolicy.exe") AND (TgtProcCmdLine containsCIS "ftp://" OR TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://")))

```