# proc_creation_win_wmic_eventconsumer_creation

## Title
New ActiveScriptEventConsumer Created Via Wmic.EXE

## ID
ebef4391-1a81-4761-a40a-1db446c0e625

## Author
Florian Roth (Nextron Systems)

## Date
2021-06-25

## Tags
attack.persistence, attack.t1546.003

## Description
Detects WMIC executions in which an event consumer gets created. This could be used to establish persistence

## References
https://twitter.com/johnlatwc/status/1408062131321270282?s=12
https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf

## False Positives
Legitimate software creating script event consumers

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "ActiveScriptEventConsumer" AND TgtProcCmdLine containsCIS " CREATE "))

```