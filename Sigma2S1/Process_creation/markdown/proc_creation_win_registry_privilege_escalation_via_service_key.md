# proc_creation_win_registry_privilege_escalation_via_service_key

## Title
Potential Privilege Escalation via Service Permissions Weakness

## ID
0f9c21f1-6a73-4b0e-9809-cb562cb8d981

## Author
Teymur Kheirkhabarov

## Date
2019-10-26

## Tags
attack.privilege-escalation, attack.t1574.011

## Description
Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level

## References
https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
https://pentestlab.blog/2017/03/31/insecure-registry-permissions/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\ImagePath" OR TgtProcCmdLine containsCIS "\FailureCommand" OR TgtProcCmdLine containsCIS "\ServiceDll") AND (TgtProcCmdLine containsCIS "ControlSet" AND TgtProcCmdLine containsCIS "services") AND (TgtProcIntegrityLevel In ("Medium","S-1-16-8192"))))

```