# proc_creation_win_diskshadow_script_mode_susp_location

## Title
Diskshadow Script Mode - Execution From Potential Suspicious Location

## ID
fa1a7e52-3d02-435b-81b8-00da14dd66c1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-15

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of "Diskshadow.exe" in script mode using the "/s" flag where the script is located in a potentially suspicious location.

## References
https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
https://medium.com/@cyberjyot/lolbin-execution-via-diskshadow-f6ff681a27a4
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow
https://www.lifars.com/wp-content/uploads/2022/01/GriefRansomware_Whitepaper-2.pdf
https://www.zscaler.com/blogs/security-research/technical-analysis-crytox-ransomware
https://research.checkpoint.com/2022/evilplayout-attack-against-irans-state-broadcaster/

## False Positives
False positives may occur if you execute the script from one of the paths mentioned in the rule. Apply additional filters that fits your org needs.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-s " OR TgtProcCmdLine containsCIS "/s " OR TgtProcCmdLine containsCIS "â€“s " OR TgtProcCmdLine containsCIS "â€”s " OR TgtProcCmdLine containsCIS "â€•s ") AND TgtProcImagePath endswithCIS "\diskshadow.exe" AND (TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Local\" OR TgtProcCmdLine containsCIS "\AppData\Roaming\" OR TgtProcCmdLine containsCIS "\ProgramData\" OR TgtProcCmdLine containsCIS "\Users\Public\")))

```