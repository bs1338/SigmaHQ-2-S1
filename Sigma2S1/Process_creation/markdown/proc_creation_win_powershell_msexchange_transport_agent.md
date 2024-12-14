# proc_creation_win_powershell_msexchange_transport_agent

## Title
MSExchange Transport Agent Installation

## ID
83809e84-4475-4b69-bc3e-4aad8568612f

## Author
Tobias Michalski (Nextron Systems)

## Date
2021-06-08

## Tags
attack.persistence, attack.t1505.002

## Description
Detects the Installation of a Exchange Transport Agent

## References
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=7

## False Positives
Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "Install-TransportAgent")

```