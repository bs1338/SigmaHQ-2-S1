# proc_creation_win_pua_pingcastle_script_parent

## Title
PUA - PingCastle Execution From Potentially Suspicious Parent

## ID
b37998de-a70b-4f33-b219-ec36bf433dc0

## Author
Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)

## Date
2024-01-11

## Tags
attack.reconnaissance, attack.t1595

## Description
Detects the execution of PingCastle, a tool designed to quickly assess the Active Directory security level via a script located in a potentially suspicious or uncommon location.


## References
https://github.com/vletoux/pingcastle
https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
https://github.com/fengjixuchui/Start-ADEnum/blob/e237a739db98b6104427d833004836507da36a58/Functions/Start-ADEnum.ps1#L450
https://github.com/lkys37en/Start-ADEnum/blob/5b42c54215fe5f57fc59abc52c20487d15764005/Functions/Start-ADEnum.ps1#L680
https://github.com/projectHULK/AD_Recon/blob/dde2daba9b3393a9388cbebda87068972cc0bd3b/SecurityAssessment.ps1#L2699
https://github.com/802-1x/Compliance/blob/2e53df8b6e89686a0b91116b3f42c8f717dca820/Ping%20Castle/Get-PingCastle-HTMLComplianceReport.ps1#L8
https://github.com/EvotecIT/TheDashboard/blob/481a9ce8f82f2fd55fe65220ee6486bae6df0c9d/Examples/RunReports/PingCastle.ps1

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((SrcProcCmdLine containsCIS ".bat" OR SrcProcCmdLine containsCIS ".chm" OR SrcProcCmdLine containsCIS ".cmd" OR SrcProcCmdLine containsCIS ".hta" OR SrcProcCmdLine containsCIS ".htm" OR SrcProcCmdLine containsCIS ".html" OR SrcProcCmdLine containsCIS ".js" OR SrcProcCmdLine containsCIS ".lnk" OR SrcProcCmdLine containsCIS ".ps1" OR SrcProcCmdLine containsCIS ".vbe" OR SrcProcCmdLine containsCIS ".vbs" OR SrcProcCmdLine containsCIS ".wsf") OR (SrcProcCmdLine containsCIS ":\Perflogs\" OR SrcProcCmdLine containsCIS ":\Temp\" OR SrcProcCmdLine containsCIS ":\Users\Public\" OR SrcProcCmdLine containsCIS ":\Windows\Temp\" OR SrcProcCmdLine containsCIS "\AppData\Local\Temp" OR SrcProcCmdLine containsCIS "\AppData\Roaming\" OR SrcProcCmdLine containsCIS "\Temporary Internet") OR ((SrcProcCmdLine containsCIS ":\Users\" AND SrcProcCmdLine containsCIS "\Favorites\") OR (SrcProcCmdLine containsCIS ":\Users\" AND SrcProcCmdLine containsCIS "\Favourites\") OR (SrcProcCmdLine containsCIS ":\Users\" AND SrcProcCmdLine containsCIS "\Contacts\"))) AND (SrcProcCmdLine containsCIS ".bat" OR SrcProcCmdLine containsCIS ".chm" OR SrcProcCmdLine containsCIS ".cmd" OR SrcProcCmdLine containsCIS ".hta" OR SrcProcCmdLine containsCIS ".htm" OR SrcProcCmdLine containsCIS ".html" OR SrcProcCmdLine containsCIS ".js" OR SrcProcCmdLine containsCIS ".lnk" OR SrcProcCmdLine containsCIS ".ps1" OR SrcProcCmdLine containsCIS ".vbe" OR SrcProcCmdLine containsCIS ".vbs" OR SrcProcCmdLine containsCIS ".wsf") AND (TgtProcImagePath endswithCIS "\PingCastle.exe" OR TgtProcDisplayName = "Ping Castle" OR (TgtProcCmdLine containsCIS "--scanner aclcheck" OR TgtProcCmdLine containsCIS "--scanner antivirus" OR TgtProcCmdLine containsCIS "--scanner computerversion" OR TgtProcCmdLine containsCIS "--scanner foreignusers" OR TgtProcCmdLine containsCIS "--scanner laps_bitlocker" OR TgtProcCmdLine containsCIS "--scanner localadmin" OR TgtProcCmdLine containsCIS "--scanner nullsession" OR TgtProcCmdLine containsCIS "--scanner nullsession-trust" OR TgtProcCmdLine containsCIS "--scanner oxidbindings" OR TgtProcCmdLine containsCIS "--scanner remote" OR TgtProcCmdLine containsCIS "--scanner share" OR TgtProcCmdLine containsCIS "--scanner smb" OR TgtProcCmdLine containsCIS "--scanner smb3querynetwork" OR TgtProcCmdLine containsCIS "--scanner spooler" OR TgtProcCmdLine containsCIS "--scanner startup" OR TgtProcCmdLine containsCIS "--scanner zerologon") OR TgtProcCmdLine containsCIS "--no-enum-limit" OR (TgtProcCmdLine containsCIS "--healthcheck" AND TgtProcCmdLine containsCIS "--level Full") OR (TgtProcCmdLine containsCIS "--healthcheck" AND TgtProcCmdLine containsCIS "--server "))))

```