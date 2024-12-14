# proc_creation_win_cmstp_execution_by_creation

## Title
CMSTP Execution Process Creation

## ID
7d4cdc5a-0076-40ca-aac8-f7e714570e47

## Author
Nik Seetharaman

## Date
2018-07-16

## Tags
attack.defense-evasion, attack.execution, attack.t1218.003, attack.g0069, car.2019-04-001

## Description
Detects various indicators of Microsoft Connection Manager Profile Installer execution

## References
https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/

## False Positives
Legitimate CMSTP use (unlikely in modern enterprise environments)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\cmstp.exe")

```