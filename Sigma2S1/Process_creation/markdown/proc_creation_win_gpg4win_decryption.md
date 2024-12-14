# proc_creation_win_gpg4win_decryption

## Title
File Decryption Using Gpg4win

## ID
037dcd71-33a8-4392-bb01-293c94663e5a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-09

## Tags
attack.execution

## Description
Detects usage of Gpg4win to decrypt files

## References
https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
https://www.gpg4win.de/documentation.html
https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -d " AND TgtProcCmdLine containsCIS "passphrase") AND ((TgtProcImagePath endswithCIS "\gpg.exe" OR TgtProcImagePath endswithCIS "\gpg2.exe") OR TgtProcDisplayName = "GnuPGâ€™s OpenPGP tool")))

```