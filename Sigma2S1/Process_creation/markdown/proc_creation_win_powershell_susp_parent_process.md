# proc_creation_win_powershell_susp_parent_process

## Title
Suspicious PowerShell Parent Process

## ID
754ed792-634f-40ae-b3bc-e0448d33f695

## Author
Teymur Kheirkhabarov, Harish Segar

## Date
2020-03-20

## Tags
attack.execution, attack.t1059.001

## Description
Detects a suspicious or uncommon parent processes of PowerShell

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=26

## False Positives
Other scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath containsCIS "tomcat" OR (SrcProcImagePath endswithCIS "\amigo.exe" OR SrcProcImagePath endswithCIS "\browser.exe" OR SrcProcImagePath endswithCIS "\chrome.exe" OR SrcProcImagePath endswithCIS "\firefox.exe" OR SrcProcImagePath endswithCIS "\httpd.exe" OR SrcProcImagePath endswithCIS "\iexplore.exe" OR SrcProcImagePath endswithCIS "\jbosssvc.exe" OR SrcProcImagePath endswithCIS "\microsoftedge.exe" OR SrcProcImagePath endswithCIS "\microsoftedgecp.exe" OR SrcProcImagePath endswithCIS "\MicrosoftEdgeSH.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\nginx.exe" OR SrcProcImagePath endswithCIS "\outlook.exe" OR SrcProcImagePath endswithCIS "\php-cgi.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\safari.exe" OR SrcProcImagePath endswithCIS "\services.exe" OR SrcProcImagePath endswithCIS "\sqlagent.exe" OR SrcProcImagePath endswithCIS "\sqlserver.exe" OR SrcProcImagePath endswithCIS "\sqlservr.exe" OR SrcProcImagePath endswithCIS "\vivaldi.exe" OR SrcProcImagePath endswithCIS "\w3wp.exe")) AND ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") OR (TgtProcCmdLine containsCIS "/c powershell" OR TgtProcCmdLine containsCIS "/c pwsh") OR TgtProcDisplayName = "Windows PowerShell" OR TgtProcDisplayName = "PowerShell Core 6")))

```