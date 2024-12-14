# proc_creation_win_powershell_user_discovery_get_aduser

## Title
User Discovery And Export Via Get-ADUser Cmdlet

## ID
1114e048-b69c-4f41-bc20-657245ae6e3f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-09

## Tags
attack.discovery, attack.t1033

## Description
Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file

## References
http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/

## False Positives
Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " > " OR TgtProcCmdLine containsCIS " | Select " OR TgtProcCmdLine containsCIS "Out-File" OR TgtProcCmdLine containsCIS "Set-Content" OR TgtProcCmdLine containsCIS "Add-Content") AND (TgtProcCmdLine containsCIS "Get-ADUser " AND TgtProcCmdLine containsCIS " -Filter \*")) AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```