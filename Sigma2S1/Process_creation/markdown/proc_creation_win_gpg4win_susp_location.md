# proc_creation_win_gpg4win_susp_location

## Title
File Encryption/Decryption Via Gpg4win From Suspicious Locations

## ID
e1e0b7d7-e10b-4ee4-ac49-a4bda05d320d

## Author
Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)

## Date
2022-11-30

## Tags
attack.execution

## Description
Detects usage of Gpg4win to encrypt/decrypt files located in potentially suspicious locations.

## References
https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "-passphrase" AND ((TgtProcImagePath endswithCIS "\gpg.exe" OR TgtProcImagePath endswithCIS "\gpg2.exe") OR TgtProcDisplayName = "GNU Privacy Guard (GnuPG)" OR TgtProcDisplayName = "GnuPGâ€™s OpenPGP tool") AND (TgtProcCmdLine containsCIS ":\PerfLogs\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Roaming\")))

```