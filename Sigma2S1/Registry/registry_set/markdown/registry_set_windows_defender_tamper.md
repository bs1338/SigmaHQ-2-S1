# registry_set_windows_defender_tamper

## Title
Disable Windows Defender Functionalities Via Registry Keys

## ID
0eb46774-f1ab-4a74-8238-1155855f2263

## Author
AlertIQ, Ján Trenčanský, frack113, Nasreddine Bencherchali, Swachchhanda Shrawan Poudel

## Date
2022-08-01

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects when attackers or tools disable Windows Defender functionalities via the Windows registry

## References
https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105
https://admx.help/?Category=Windows_7_2008R2&Policy=Microsoft.Policies.WindowsDefender::SpyNetReporting
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html
https://www.tenforums.com/tutorials/105533-enable-disable-windows-defender-exploit-protection-settings.html
https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-microsoft-defender-antivirus.html
https://securelist.com/key-group-ransomware-samples-and-telegram-schemes/114025/

## False Positives
Administrator actions via the Windows Defender interface
Third party Antivirus

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows Defender\" OR RegistryKeyPath containsCIS "\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\" OR RegistryKeyPath containsCIS "\SOFTWARE\Policies\Microsoft\Windows Defender\") AND ((RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "\DisallowExploitProtectionOverride" OR RegistryKeyPath endswithCIS "\Features\TamperProtection" OR RegistryKeyPath endswithCIS "\MpEngine\MpEnablePus" OR RegistryKeyPath endswithCIS "\PUAProtection" OR RegistryKeyPath endswithCIS "\Signature Update\ForceUpdateFromMU" OR RegistryKeyPath endswithCIS "\SpyNet\SpynetReporting" OR RegistryKeyPath endswithCIS "\SpyNet\SubmitSamplesConsent" OR RegistryKeyPath endswithCIS "\Windows Defender Exploit Guard\Controlled Folder Access\EnableControlledFolderAccess")) OR (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath endswithCIS "\DisableAntiSpyware" OR RegistryKeyPath endswithCIS "\DisableAntiVirus" OR RegistryKeyPath endswithCIS "\DisableBehaviorMonitoring" OR RegistryKeyPath endswithCIS "\DisableBlockAtFirstSeen" OR RegistryKeyPath endswithCIS "\DisableEnhancedNotifications" OR RegistryKeyPath endswithCIS "\DisableIntrusionPreventionSystem" OR RegistryKeyPath endswithCIS "\DisableIOAVProtection" OR RegistryKeyPath endswithCIS "\DisableOnAccessProtection" OR RegistryKeyPath endswithCIS "\DisableRealtimeMonitoring" OR RegistryKeyPath endswithCIS "\DisableScanOnRealtimeEnable" OR RegistryKeyPath endswithCIS "\DisableScriptScanning"))) AND (NOT (SrcProcImagePath endswithCIS "\sepWscSvc64.exe" AND SrcProcImagePath startswithCIS "C:\Program Files\Symantec\Symantec Endpoint Protection\"))))

```