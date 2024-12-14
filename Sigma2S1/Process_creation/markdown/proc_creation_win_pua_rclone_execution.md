# proc_creation_win_pua_rclone_execution

## Title
PUA - Rclone Execution

## ID
e37db05d-d1f9-49c8-b464-cee1a4b11638

## Author
Bhabesh Raj, Sittikorn S, Aaron Greetham (@beardofbinary) - NCC Group

## Date
2021-05-10

## Tags
attack.exfiltration, attack.t1567.002

## Description
Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc

## References
https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/
https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware
https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a
https://labs.sentinelone.com/egregor-raas-continues-the-chaos-with-cobalt-strike-and-rclone
https://www.splunk.com/en_us/blog/security/darkside-ransomware-splunk-threat-update-and-detections.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "--config " AND TgtProcCmdLine containsCIS "--no-check-certificate " AND TgtProcCmdLine containsCIS " copy ") OR ((TgtProcCmdLine containsCIS "pass" OR TgtProcCmdLine containsCIS "user" OR TgtProcCmdLine containsCIS "copy" OR TgtProcCmdLine containsCIS "sync" OR TgtProcCmdLine containsCIS "config" OR TgtProcCmdLine containsCIS "lsd" OR TgtProcCmdLine containsCIS "remote" OR TgtProcCmdLine containsCIS "ls" OR TgtProcCmdLine containsCIS "mega" OR TgtProcCmdLine containsCIS "pcloud" OR TgtProcCmdLine containsCIS "ftp" OR TgtProcCmdLine containsCIS "ignore-existing" OR TgtProcCmdLine containsCIS "auto-confirm" OR TgtProcCmdLine containsCIS "transfers" OR TgtProcCmdLine containsCIS "multi-thread-streams" OR TgtProcCmdLine containsCIS "no-check-certificate ") AND (TgtProcImagePath endswithCIS "\rclone.exe" OR TgtProcDisplayName = "Rsync for cloud storage"))))

```