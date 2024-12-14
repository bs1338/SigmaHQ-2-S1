# proc_creation_win_susp_shadow_copies_creation

## Title
Shadow Copies Creation Using Operating Systems Utilities

## ID
b17ea6f7-6e90-447e-a799-e6c0a493d6ce

## Author
Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community

## Date
2019-10-22

## Tags
attack.credential-access, attack.t1003, attack.t1003.002, attack.t1003.003

## Description
Shadow Copies creation using operating systems utilities, possible credential access

## References
https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tutorial-for-ntds-goodness-vssadmin-wmis-ntdsdit-system/

## False Positives
Legitimate administrator working with shadow copies, access for backup purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "shadow" AND TgtProcCmdLine containsCIS "create") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\vssadmin.exe")))

```