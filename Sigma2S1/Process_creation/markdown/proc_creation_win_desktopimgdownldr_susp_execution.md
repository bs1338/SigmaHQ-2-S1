# proc_creation_win_desktopimgdownldr_susp_execution

## Title
Suspicious Desktopimgdownldr Command

## ID
bb58aa4a-b80b-415a-a2c0-2f65a4c81009

## Author
Florian Roth (Nextron Systems)

## Date
2020-07-03

## Tags
attack.command-and-control, attack.t1105

## Description
Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet

## References
https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
https://twitter.com/SBousseaden/status/1278977301745741825

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /lockscreenurl:" AND (NOT (TgtProcCmdLine containsCIS ".jpg" OR TgtProcCmdLine containsCIS ".jpeg" OR TgtProcCmdLine containsCIS ".png"))) OR (TgtProcCmdLine containsCIS "reg delete" AND TgtProcCmdLine containsCIS "\PersonalizationCSP")))

```