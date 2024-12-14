# proc_creation_win_reg_windows_defender_tamper

## Title
Suspicious Windows Defender Registry Key Tampering Via Reg.EXE

## ID
452bce90-6fb0-43cc-97a5-affc283139b3

## Author
Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-03-22

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects the usage of "reg.exe" to tamper with different Windows Defender registry keys in order to disable some important features related to protection and detection

## References
https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/
https://github.com/swagkarna/Defeat-Defender-V1.2.0
https://www.elevenforum.com/t/video-guide-how-to-completely-disable-microsoft-defender-antivirus.14608/page-2

## False Positives
Rare legitimate use by administrators to test software (should always be investigated)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\reg.exe" AND (TgtProcCmdLine containsCIS "SOFTWARE\Microsoft\Windows Defender\" OR TgtProcCmdLine containsCIS "SOFTWARE\Policies\Microsoft\Windows Defender Security Center" OR TgtProcCmdLine containsCIS "SOFTWARE\Policies\Microsoft\Windows Defender\")) AND (((TgtProcCmdLine containsCIS "DisallowExploitProtectionOverride" OR TgtProcCmdLine containsCIS "EnableControlledFolderAccess" OR TgtProcCmdLine containsCIS "MpEnablePus" OR TgtProcCmdLine containsCIS "PUAProtection" OR TgtProcCmdLine containsCIS "SpynetReporting" OR TgtProcCmdLine containsCIS "SubmitSamplesConsent" OR TgtProcCmdLine containsCIS "TamperProtection") AND (TgtProcCmdLine containsCIS " add " AND TgtProcCmdLine containsCIS "d 0")) OR ((TgtProcCmdLine containsCIS "DisableAntiSpyware" OR TgtProcCmdLine containsCIS "DisableAntiSpywareRealtimeProtection" OR TgtProcCmdLine containsCIS "DisableAntiVirus" OR TgtProcCmdLine containsCIS "DisableArchiveScanning" OR TgtProcCmdLine containsCIS "DisableBehaviorMonitoring" OR TgtProcCmdLine containsCIS "DisableBlockAtFirstSeen" OR TgtProcCmdLine containsCIS "DisableConfig" OR TgtProcCmdLine containsCIS "DisableEnhancedNotifications" OR TgtProcCmdLine containsCIS "DisableIntrusionPreventionSystem" OR TgtProcCmdLine containsCIS "DisableIOAVProtection" OR TgtProcCmdLine containsCIS "DisableOnAccessProtection" OR TgtProcCmdLine containsCIS "DisablePrivacyMode" OR TgtProcCmdLine containsCIS "DisableRealtimeMonitoring" OR TgtProcCmdLine containsCIS "DisableRoutinelyTakingAction" OR TgtProcCmdLine containsCIS "DisableScanOnRealtimeEnable" OR TgtProcCmdLine containsCIS "DisableScriptScanning" OR TgtProcCmdLine containsCIS "Notification_Suppress" OR TgtProcCmdLine containsCIS "SignatureDisableUpdateOnStartupWithoutEngine") AND (TgtProcCmdLine containsCIS " add " AND TgtProcCmdLine containsCIS "d 1")))))

```