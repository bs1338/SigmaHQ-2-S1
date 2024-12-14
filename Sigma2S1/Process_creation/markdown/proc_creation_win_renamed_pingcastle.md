# proc_creation_win_renamed_pingcastle

## Title
Renamed PingCastle Binary Execution

## ID
2433a154-bb3d-42e4-86c3-a26bdac91c45

## Author
Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)

## Date
2024-01-11

## Tags
attack.execution, attack.t1059, attack.defense-evasion, attack.t1202

## Description
Detects the execution of a renamed "PingCastle" binary based on the PE metadata fields.

## References
https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
https://www.pingcastle.com/documentation/scanner/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "--scanner aclcheck" OR TgtProcCmdLine containsCIS "--scanner antivirus" OR TgtProcCmdLine containsCIS "--scanner computerversion" OR TgtProcCmdLine containsCIS "--scanner foreignusers" OR TgtProcCmdLine containsCIS "--scanner laps_bitlocker" OR TgtProcCmdLine containsCIS "--scanner localadmin" OR TgtProcCmdLine containsCIS "--scanner nullsession" OR TgtProcCmdLine containsCIS "--scanner nullsession-trust" OR TgtProcCmdLine containsCIS "--scanner oxidbindings" OR TgtProcCmdLine containsCIS "--scanner remote" OR TgtProcCmdLine containsCIS "--scanner share" OR TgtProcCmdLine containsCIS "--scanner smb" OR TgtProcCmdLine containsCIS "--scanner smb3querynetwork" OR TgtProcCmdLine containsCIS "--scanner spooler" OR TgtProcCmdLine containsCIS "--scanner startup" OR TgtProcCmdLine containsCIS "--scanner zerologon") OR TgtProcCmdLine containsCIS "--no-enum-limit" OR (TgtProcCmdLine containsCIS "--healthcheck" AND TgtProcCmdLine containsCIS "--level Full") OR (TgtProcCmdLine containsCIS "--healthcheck" AND TgtProcCmdLine containsCIS "--server ")) AND (NOT (TgtProcImagePath endswithCIS "\PingCastleReporting.exe" OR TgtProcImagePath endswithCIS "\PingCastleCloud.exe" OR TgtProcImagePath endswithCIS "\PingCastle.exe"))))

```