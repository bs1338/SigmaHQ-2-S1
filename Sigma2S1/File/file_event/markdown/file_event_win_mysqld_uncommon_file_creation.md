# file_event_win_mysqld_uncommon_file_creation

## Title
Uncommon File Creation By Mysql Daemon Process

## ID
c61daa90-3c1e-4f18-af62-8f288b5c9aaf

## Author
Joseph Kamau

## Date
2024-05-27

## Tags
attack.defense-evasion

## Description
Detects the creation of files with scripting or executable extensions by Mysql daemon.
Which could be an indicator of "User Defined Functions" abuse to download malware.


## References
https://asec.ahnlab.com/en/58878/
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/honeypot-recon-mysql-malware-infection-via-user-defined-functions-udf/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\mysqld.exe" OR SrcProcImagePath endswithCIS "\mysqld-nt.exe") AND (TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".dat" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".psm1" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".vbs")))

```