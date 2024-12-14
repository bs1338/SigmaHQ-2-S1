# proc_creation_win_susp_copy_lateral_movement

## Title
Copy From Or To Admin Share Or Sysvol Folder

## ID
855bc8b5-2ae8-402e-a9ed-b889e6df1900

## Author
Florian Roth (Nextron Systems), oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Nasreddine Bencherchali

## Date
2019-12-30

## Tags
attack.lateral-movement, attack.collection, attack.exfiltration, attack.t1039, attack.t1048, attack.t1021.002

## Description
Detects a copy command or a copy utility execution to or from an Admin share or remote

## References
https://twitter.com/SBousseaden/status/1211636381086339073
https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
https://www.elastic.co/guide/en/security/current/remote-file-copy-to-a-hidden-share.html
https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/

## False Positives
Administrative scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine = "*\\*$*" OR TgtProcCmdLine containsCIS "\Sysvol\") AND ((TgtProcImagePath endswithCIS "\robocopy.exe" OR TgtProcImagePath endswithCIS "\xcopy.exe") OR (TgtProcCmdLine containsCIS "copy" AND TgtProcImagePath endswithCIS "\cmd.exe") OR ((TgtProcCmdLine containsCIS "copy-item" OR TgtProcCmdLine containsCIS "copy " OR TgtProcCmdLine containsCIS "cpi " OR TgtProcCmdLine containsCIS " cp " OR TgtProcCmdLine containsCIS "move " OR TgtProcCmdLine containsCIS "move-item" OR TgtProcCmdLine containsCIS " mi " OR TgtProcCmdLine containsCIS " mv ") AND (TgtProcImagePath containsCIS "\powershell.exe" OR TgtProcImagePath containsCIS "\pwsh.exe")))))

```