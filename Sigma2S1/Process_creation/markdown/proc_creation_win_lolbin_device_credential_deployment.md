# proc_creation_win_lolbin_device_credential_deployment

## Title
DeviceCredentialDeployment Execution

## ID
b8b1b304-a60f-4999-9a6e-c547bde03ffd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the execution of DeviceCredentialDeployment to hide a process from view

## References
https://github.com/LOLBAS-Project/LOLBAS/pull/147

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\DeviceCredentialDeployment.exe")

```