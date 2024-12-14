# proc_creation_win_sysinternals_sysmon_config_update

## Title
Sysmon Configuration Update

## ID
87911521-7098-470b-a459-9a57fc80bdfd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-09

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects updates to Sysmon's configuration. Attackers might update or replace the Sysmon configuration with a bare bone one to avoid monitoring without shutting down the service completely

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

## False Positives
Legitimate administrators might use this command to update Sysmon configuration.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-c" OR TgtProcCmdLine containsCIS "/c" OR TgtProcCmdLine containsCIS "â€“c" OR TgtProcCmdLine containsCIS "â€”c" OR TgtProcCmdLine containsCIS "â€•c") AND ((TgtProcImagePath endswithCIS "\Sysmon64.exe" OR TgtProcImagePath endswithCIS "\Sysmon.exe") OR TgtProcDisplayName = "System activity monitor")))

```