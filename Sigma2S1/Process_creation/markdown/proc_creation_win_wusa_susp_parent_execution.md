# proc_creation_win_wusa_susp_parent_execution

## Title
Wusa.EXE Executed By Parent Process Located In Suspicious Location

## ID
ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99

## Author
X__Junior (Nextron Systems)

## Date
2023-11-26

## Tags
attack.execution

## Description
Detects execution of the "wusa.exe" (Windows Update Standalone Installer) utility by a parent process that is located in a suspicious location.
Attackers could instantiate an instance of "wusa.exe" in order to bypass User Account Control (UAC). They can duplicate the access token from "wusa.exe" to gain elevated privileges.


## References
https://www.fortinet.com/blog/threat-research/konni-campaign-distributed-via-malicious-document

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\wusa.exe" AND ((SrcProcImagePath containsCIS ":\Perflogs\" OR SrcProcImagePath containsCIS ":\Users\Public\" OR SrcProcImagePath containsCIS ":\Windows\Temp\" OR SrcProcImagePath containsCIS "\Appdata\Local\Temp\" OR SrcProcImagePath containsCIS "\Temporary Internet") OR ((SrcProcImagePath containsCIS ":\Users\" AND SrcProcImagePath containsCIS "\Favorites\") OR (SrcProcImagePath containsCIS ":\Users\" AND SrcProcImagePath containsCIS "\Favourites\") OR (SrcProcImagePath containsCIS ":\Users\" AND SrcProcImagePath containsCIS "\Contacts\") OR (SrcProcImagePath containsCIS ":\Users\" AND SrcProcImagePath containsCIS "\Pictures\"))) AND (NOT TgtProcCmdLine containsCIS ".msu")))

```