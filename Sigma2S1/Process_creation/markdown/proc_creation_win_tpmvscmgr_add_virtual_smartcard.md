# proc_creation_win_tpmvscmgr_add_virtual_smartcard

## Title
New Virtual Smart Card Created Via TpmVscMgr.EXE

## ID
c633622e-cab9-4eaa-bb13-66a1d68b3e47

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-15

## Tags
attack.execution

## Description
Detects execution of "Tpmvscmgr.exe" to create a new virtual smart card.

## References
https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-tpmvscmgr

## False Positives
Legitimate usage by an administrator

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "create")

```