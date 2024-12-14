# proc_creation_win_netsh_fw_set_rule

## Title
Firewall Rule Update Via Netsh.EXE

## ID
a70dcb37-3bee-453a-99df-d0c683151be6

## Author
X__Junior (Nextron Systems)

## Date
2023-07-18

## Tags
attack.defense-evasion

## Description
Detects execution of netsh with the "advfirewall" and the "set" option in order to set new values for properties of a existing rule

## References
https://ss64.com/nt/netsh.html

## False Positives
Legitimate administration activity
Software installations and removal

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " firewall " AND TgtProcCmdLine containsCIS " set ") AND TgtProcImagePath endswithCIS "\netsh.exe"))

```