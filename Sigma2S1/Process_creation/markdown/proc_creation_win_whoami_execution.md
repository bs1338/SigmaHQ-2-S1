# proc_creation_win_whoami_execution

## Title
Whoami Utility Execution

## ID
e28a5a99-da44-436d-b7a0-2afc20a5f413

## Author
Florian Roth (Nextron Systems)

## Date
2018-08-13

## Tags
attack.discovery, attack.t1033, car.2016-03-001

## Description
Detects the execution of whoami, which is often used by attackers after exploitation / privilege escalation

## References
https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/

## False Positives
Admin activity
Scripts and administrative tools used in the monitored environment
Monitoring activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\whoami.exe")

```