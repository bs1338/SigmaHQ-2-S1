# proc_creation_win_wmic_recon_group

## Title
Local Groups Reconnaissance Via Wmic.EXE

## ID
164eda96-11b2-430b-85ff-6a265c15bf32

## Author
frack113

## Date
2021-12-12

## Tags
attack.discovery, attack.t1069.001

## Description
Detects the execution of "wmic" with the "group" flag.
Adversaries may attempt to find local system groups and permission settings.
The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group.
Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.001/T1069.001.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " group" AND TgtProcImagePath endswithCIS "\wmic.exe"))

```