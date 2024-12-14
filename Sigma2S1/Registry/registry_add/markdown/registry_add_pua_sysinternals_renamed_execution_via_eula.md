# registry_add_pua_sysinternals_renamed_execution_via_eula

## Title
Suspicious Execution Of Renamed Sysinternals Tools - Registry

## ID
f50f3c09-557d-492d-81db-9064a8d4e211

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-24

## Tags
attack.resource-development, attack.t1588.002

## Description
Detects the creation of the "accepteula" key related to the Sysinternals tools being created from executables with the wrong name (e.g. a renamed Sysinternals tool)

## References
Internal Research

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((EventType = "CreateKey" AND (RegistryKeyPath containsCIS "\Active Directory Explorer" OR RegistryKeyPath containsCIS "\Handle" OR RegistryKeyPath containsCIS "\LiveKd" OR RegistryKeyPath containsCIS "\ProcDump" OR RegistryKeyPath containsCIS "\Process Explorer" OR RegistryKeyPath containsCIS "\PsExec" OR RegistryKeyPath containsCIS "\PsLoggedon" OR RegistryKeyPath containsCIS "\PsLoglist" OR RegistryKeyPath containsCIS "\PsPasswd" OR RegistryKeyPath containsCIS "\PsPing" OR RegistryKeyPath containsCIS "\PsService" OR RegistryKeyPath containsCIS "\SDelete") AND RegistryKeyPath endswithCIS "\EulaAccepted") AND (NOT (SrcProcImagePath endswithCIS "\ADExplorer.exe" OR SrcProcImagePath endswithCIS "\ADExplorer64.exe" OR SrcProcImagePath endswithCIS "\handle.exe" OR SrcProcImagePath endswithCIS "\handle64.exe" OR SrcProcImagePath endswithCIS "\livekd.exe" OR SrcProcImagePath endswithCIS "\livekd64.exe" OR SrcProcImagePath endswithCIS "\procdump.exe" OR SrcProcImagePath endswithCIS "\procdump64.exe" OR SrcProcImagePath endswithCIS "\procexp.exe" OR SrcProcImagePath endswithCIS "\procexp64.exe" OR SrcProcImagePath endswithCIS "\PsExec.exe" OR SrcProcImagePath endswithCIS "\PsExec64.exe" OR SrcProcImagePath endswithCIS "\PsLoggedon.exe" OR SrcProcImagePath endswithCIS "\PsLoggedon64.exe" OR SrcProcImagePath endswithCIS "\psloglist.exe" OR SrcProcImagePath endswithCIS "\psloglist64.exe" OR SrcProcImagePath endswithCIS "\pspasswd.exe" OR SrcProcImagePath endswithCIS "\pspasswd64.exe" OR SrcProcImagePath endswithCIS "\PsPing.exe" OR SrcProcImagePath endswithCIS "\PsPing64.exe" OR SrcProcImagePath endswithCIS "\PsService.exe" OR SrcProcImagePath endswithCIS "\PsService64.exe" OR SrcProcImagePath endswithCIS "\sdelete.exe"))))

```