# registry_event_cmstp_execution_by_registry

## Title
CMSTP Execution Registry Event

## ID
b6d235fc-1d38-4b12-adbe-325f06728f37

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
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\cmmgr32.exe")

```