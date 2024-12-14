# proc_creation_win_uac_bypass_wsreset

## Title
Bypass UAC via WSReset.exe

## ID
d797268e-28a9-49a7-b9a8-2f5039011c5c

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community, Florian Roth

## Date
2019-10-24

## Tags
attack.privilege-escalation, attack.defense-evasion, attack.t1548.002

## Description
Detects use of WSReset.exe to bypass User Account Control (UAC). Adversaries use this technique to execute privileged processes.

## References
https://eqllib.readthedocs.io/en/latest/analytics/532b5ed4-7930-11e9-8f5c-d46d6d62a49e.html
https://lolbas-project.github.io/lolbas/Binaries/Wsreset/
https://www.activecyber.us/activelabs/windows-uac-bypass
https://twitter.com/ReaQta/status/1222548288731217921

## False Positives
Unknown sub processes of Wsreset.exe

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\wsreset.exe" AND (NOT TgtProcImagePath endswithCIS "\conhost.exe")))

```