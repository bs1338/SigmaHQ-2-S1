# proc_creation_win_auditpol_susp_execution

## Title
Audit Policy Tampering Via Auditpol

## ID
0a13e132-651d-11eb-ae93-0242ac130002

## Author
Janantha Marasinghe (https://github.com/blueteam0ps)

## Date
2021-02-02

## Tags
attack.defense-evasion, attack.t1562.002

## Description
Threat actors can use auditpol binary to change audit policy configuration to impair detection capability.
This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor.


## References
https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/

## False Positives
Administrator or administrator scripts might leverage the flags mentioned in the detection section. Either way, it should always be monitored

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "disable" OR TgtProcCmdLine containsCIS "clear" OR TgtProcCmdLine containsCIS "remove" OR TgtProcCmdLine containsCIS "restore") AND TgtProcImagePath endswithCIS "\auditpol.exe"))

```