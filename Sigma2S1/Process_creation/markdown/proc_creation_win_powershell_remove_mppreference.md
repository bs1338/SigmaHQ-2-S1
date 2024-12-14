# proc_creation_win_powershell_remove_mppreference

## Title
Tamper Windows Defender Remove-MpPreference

## ID
07e3cb2c-0608-410d-be4b-1511cb1a0448

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-05

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects attempts to remove Windows Defender configurations using the 'MpPreference' cmdlet

## References
https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-controlled-folder-access-event-search/ba-p/2326088

## False Positives
Legitimate PowerShell scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Remove-MpPreference" AND (TgtProcCmdLine containsCIS "-ControlledFolderAccessProtectedFolders " OR TgtProcCmdLine containsCIS "-AttackSurfaceReductionRules_Ids " OR TgtProcCmdLine containsCIS "-AttackSurfaceReductionRules_Actions " OR TgtProcCmdLine containsCIS "-CheckForSignaturesBeforeRunningScan ")))

```