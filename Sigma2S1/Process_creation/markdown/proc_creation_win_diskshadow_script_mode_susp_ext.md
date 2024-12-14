# proc_creation_win_diskshadow_script_mode_susp_ext

## Title
Diskshadow Script Mode - Uncommon Script Extension Execution

## ID
1dde5376-a648-492e-9e54-4241dd9b0c7f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-15

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of "Diskshadow.exe" in script mode to execute an script with a potentially uncommon extension.
Initial baselining of the allowed extension list is required.


## References
https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
https://medium.com/@cyberjyot/lolbin-execution-via-diskshadow-f6ff681a27a4
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow
https://www.lifars.com/wp-content/uploads/2022/01/GriefRansomware_Whitepaper-2.pdf
https://www.zscaler.com/blogs/security-research/technical-analysis-crytox-ransomware
https://research.checkpoint.com/2022/evilplayout-attack-against-irans-state-broadcaster/

## False Positives
False postitve might occur with legitimate or uncommon extensions used internally. Initial baseline is required.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-s " OR TgtProcCmdLine containsCIS "/s " OR TgtProcCmdLine containsCIS "â€“s " OR TgtProcCmdLine containsCIS "â€”s " OR TgtProcCmdLine containsCIS "â€•s ") AND TgtProcImagePath endswithCIS "\diskshadow.exe") AND (NOT TgtProcCmdLine containsCIS ".txt")))

```