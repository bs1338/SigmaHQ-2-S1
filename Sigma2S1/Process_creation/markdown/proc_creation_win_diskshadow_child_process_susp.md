# proc_creation_win_diskshadow_child_process_susp

## Title
Potentially Suspicious Child Process Of DiskShadow.EXE

## ID
9f546b25-5f12-4c8d-8532-5893dcb1e4b8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-15

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects potentially suspicious child processes of "Diskshadow.exe". This could be an attempt to bypass parent/child relationship detection or application whitelisting rules.

## References
https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
https://medium.com/@cyberjyot/lolbin-execution-via-diskshadow-f6ff681a27a4
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow
https://www.lifars.com/wp-content/uploads/2022/01/GriefRansomware_Whitepaper-2.pdf
https://www.zscaler.com/blogs/security-research/technical-analysis-crytox-ransomware
https://research.checkpoint.com/2022/evilplayout-attack-against-irans-state-broadcaster/

## False Positives
False postitve can occur in cases where admin scripts levreage the "exec" flag to execute applications

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\diskshadow.exe"))

```