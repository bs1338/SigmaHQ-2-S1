# registry_set_renamed_sysinternals_eula_accepted

## Title
Usage of Renamed Sysinternals Tools - RegistrySet

## ID
8023f872-3f1d-4301-a384-801889917ab4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-24

## Tags
attack.resource-development, attack.t1588.002

## Description
Detects non-sysinternals tools setting the "accepteula" key which normally is set on sysinternals tool execution

## References
Internal Research

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryKeyPath containsCIS "\PsExec" OR RegistryKeyPath containsCIS "\ProcDump" OR RegistryKeyPath containsCIS "\Handle" OR RegistryKeyPath containsCIS "\LiveKd" OR RegistryKeyPath containsCIS "\Process Explorer" OR RegistryKeyPath containsCIS "\PsLoglist" OR RegistryKeyPath containsCIS "\PsPasswd" OR RegistryKeyPath containsCIS "\Active Directory Explorer") AND RegistryKeyPath endswithCIS "\EulaAccepted") AND (NOT (SrcProcImagePath endswithCIS "\PsExec.exe" OR SrcProcImagePath endswithCIS "\PsExec64.exe" OR SrcProcImagePath endswithCIS "\procdump.exe" OR SrcProcImagePath endswithCIS "\procdump64.exe" OR SrcProcImagePath endswithCIS "\handle.exe" OR SrcProcImagePath endswithCIS "\handle64.exe" OR SrcProcImagePath endswithCIS "\livekd.exe" OR SrcProcImagePath endswithCIS "\livekd64.exe" OR SrcProcImagePath endswithCIS "\procexp.exe" OR SrcProcImagePath endswithCIS "\procexp64.exe" OR SrcProcImagePath endswithCIS "\psloglist.exe" OR SrcProcImagePath endswithCIS "\psloglist64.exe" OR SrcProcImagePath endswithCIS "\pspasswd.exe" OR SrcProcImagePath endswithCIS "\pspasswd64.exe" OR SrcProcImagePath endswithCIS "\ADExplorer.exe" OR SrcProcImagePath endswithCIS "\ADExplorer64.exe")) AND (NOT SrcProcImagePath IS NOT EMPTY)))

```