# proc_creation_win_pua_seatbelt

## Title
PUA - Seatbelt Execution

## ID
38646daa-e78f-4ace-9de0-55547b2d30da

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-18

## Tags
attack.discovery, attack.t1526, attack.t1087, attack.t1083

## Description
Detects the execution of the PUA/Recon tool Seatbelt via PE information of command line parameters

## References
https://github.com/GhostPack/Seatbelt
https://www.bluetangle.dev/2022/08/fastening-seatbelt-on-threat-hunting.html

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\Seatbelt.exe" OR TgtProcDisplayName = "Seatbelt" OR (TgtProcCmdLine containsCIS " DpapiMasterKeys" OR TgtProcCmdLine containsCIS " InterestingProcesses" OR TgtProcCmdLine containsCIS " InterestingFiles" OR TgtProcCmdLine containsCIS " CertificateThumbprints" OR TgtProcCmdLine containsCIS " ChromiumBookmarks" OR TgtProcCmdLine containsCIS " ChromiumHistory" OR TgtProcCmdLine containsCIS " ChromiumPresence" OR TgtProcCmdLine containsCIS " CloudCredentials" OR TgtProcCmdLine containsCIS " CredEnum" OR TgtProcCmdLine containsCIS " CredGuard" OR TgtProcCmdLine containsCIS " FirefoxHistory" OR TgtProcCmdLine containsCIS " ProcessCreationEvents")) OR ((TgtProcCmdLine containsCIS " -group=misc" OR TgtProcCmdLine containsCIS " -group=remote" OR TgtProcCmdLine containsCIS " -group=chromium" OR TgtProcCmdLine containsCIS " -group=slack" OR TgtProcCmdLine containsCIS " -group=system" OR TgtProcCmdLine containsCIS " -group=user" OR TgtProcCmdLine containsCIS " -group=all") AND TgtProcCmdLine containsCIS " -outputfile=")))

```