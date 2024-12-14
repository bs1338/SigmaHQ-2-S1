# proc_creation_win_ultravnc_susp_execution

## Title
Suspicious UltraVNC Execution

## ID
871b9555-69ca-4993-99d3-35a59f9f3599

## Author
Bhabesh Raj

## Date
2022-03-04

## Tags
attack.lateral-movement, attack.g0047, attack.t1021.005

## Description
Detects suspicious UltraVNC command line flag combination that indicate a auto reconnect upon execution, e.g. startup (as seen being used by Gamaredon threat group)

## References
https://web.archive.org/web/20220224045756/https://www.ria.ee/sites/default/files/content-editors/kuberturve/tale_of_gamaredon_infection.pdf
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-gamaredon-espionage-ukraine
https://unit42.paloaltonetworks.com/unit-42-title-gamaredon-group-toolset-evolution
https://uvnc.com/docs/uvnc-viewer/52-ultravnc-viewer-commandline-parameters.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "-autoreconnect " AND TgtProcCmdLine containsCIS "-connect " AND TgtProcCmdLine containsCIS "-id:"))

```