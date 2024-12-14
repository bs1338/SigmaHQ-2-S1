# proc_creation_win_csvde_export

## Title
Active Directory Structure Export Via Csvde.EXE

## ID
e5d36acd-acb4-4c6f-a13f-9eb203d50099

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-14

## Tags
attack.exfiltration, attack.discovery, attack.t1087.002

## Description
Detects the execution of "csvde.exe" in order to export organizational Active Directory structure.

## References
https://www.cybereason.com/blog/research/operation-ghostshell-novel-rat-targets-global-aerospace-and-telecoms-firms
https://web.archive.org/web/20180725233601/https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf
https://businessinsights.bitdefender.com/deep-dive-into-a-backdoordiplomacy-attack-a-study-of-an-attackers-toolkit
https://redcanary.com/blog/msix-installers/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\csvde.exe" AND TgtProcCmdLine containsCIS " -f") AND (NOT TgtProcCmdLine containsCIS " -i")))

```