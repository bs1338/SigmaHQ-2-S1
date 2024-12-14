# proc_creation_win_auditpol_nt_resource_kit_usage

## Title
Audit Policy Tampering Via NT Resource Kit Auditpol

## ID
c6c56ada-612b-42d1-9a29-adad3c5c2c1e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2021-12-18

## Tags
attack.defense-evasion, attack.t1562.002

## Description
Threat actors can use an older version of the auditpol binary available inside the NT resource kit to change audit policy configuration to impair detection capability.
This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor.


## References
https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Windows%202000%20Resource%20Kit%20Tools/AuditPol

## False Positives
The old auditpol utility isn't available by default on recent versions of Windows as it was replaced by a newer version. The FP rate should be very low except for tools that use a similar flag structure

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/logon:none" OR TgtProcCmdLine containsCIS "/system:none" OR TgtProcCmdLine containsCIS "/sam:none" OR TgtProcCmdLine containsCIS "/privilege:none" OR TgtProcCmdLine containsCIS "/object:none" OR TgtProcCmdLine containsCIS "/process:none" OR TgtProcCmdLine containsCIS "/policy:none"))

```