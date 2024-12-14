# proc_creation_win_hktl_edrsilencer

## Title
HackTool - EDRSilencer Execution

## ID
eb2d07d4-49cb-4523-801a-da002df36602

## Author
@gott_cyber

## Date
2024-01-02

## Tags
attack.defense-evasion, attack.t1562

## Description
Detects the execution of EDRSilencer, a tool that leverages Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server based on PE metadata information.


## References
https://github.com/netero1010/EDRSilencer

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\EDRSilencer.exe" OR TgtProcDisplayName containsCIS "EDRSilencer"))

```