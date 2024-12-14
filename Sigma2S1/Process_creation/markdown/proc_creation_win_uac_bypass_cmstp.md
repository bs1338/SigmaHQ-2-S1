# proc_creation_win_uac_bypass_cmstp

## Title
Bypass UAC via CMSTP

## ID
e66779cc-383e-4224-a3a4-267eeb585c40

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community

## Date
2019-10-24

## Tags
attack.privilege-escalation, attack.defense-evasion, attack.t1548.002, attack.t1218.003

## Description
Detect commandline usage of Microsoft Connection Manager Profile Installer (cmstp.exe) to install specially formatted local .INF files

## References
https://eqllib.readthedocs.io/en/latest/analytics/e584f1a1-c303-4885-8a66-21360c90995b.html
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.003/T1218.003.md
https://lolbas-project.github.io/lolbas/Binaries/Cmstp/

## False Positives
Legitimate use of cmstp.exe utility by legitimate user

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/s" OR TgtProcCmdLine containsCIS "-s" OR TgtProcCmdLine containsCIS "/au" OR TgtProcCmdLine containsCIS "-au" OR TgtProcCmdLine containsCIS "/ni" OR TgtProcCmdLine containsCIS "-ni") AND TgtProcImagePath endswithCIS "\cmstp.exe"))

```