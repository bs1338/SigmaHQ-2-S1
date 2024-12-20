# proc_creation_win_whoami_output

## Title
Whoami.EXE Execution With Output Option

## ID
c30fb093-1109-4dc8-88a8-b30d11c95a5d

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-28

## Tags
attack.discovery, attack.t1033, car.2016-03-001

## Description
Detects the execution of "whoami.exe" with the "/FO" flag to choose CSV as output format or with redirection options to export the results to a file for later use.

## References
https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
https://www.youtube.com/watch?v=DsJ9ByX84o4&t=6s

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " /FO CSV" OR TgtProcCmdLine containsCIS " -FO CSV") AND TgtProcImagePath endswithCIS "\whoami.exe") OR TgtProcCmdLine = "*whoami*>*"))

```