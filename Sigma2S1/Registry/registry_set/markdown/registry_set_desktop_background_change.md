# registry_set_desktop_background_change

## Title
Potentially Suspicious Desktop Background Change Via Registry

## ID
85b88e05-dadc-430b-8a9e-53ff1cd30aae

## Author
Nasreddine Bencherchali (Nextron Systems), Stephen Lincoln @slincoln-aiq (AttackIQ)

## Date
2023-12-21

## Tags
attack.defense-evasion, attack.impact, attack.t1112, attack.t1491.001

## Description
Detects registry value settings that would replace the user's desktop background.
This is a common technique used by malware to change the desktop background to a ransom note or other image.


## References
https://www.attackiq.com/2023/09/20/emulating-rhysida/
https://research.checkpoint.com/2023/the-rhysida-ransomware-activity-analysis-and-ties-to-vice-society/
https://www.trendmicro.com/en_us/research/23/h/an-overview-of-the-new-rhysida-ransomware.html
https://www.virustotal.com/gui/file/a864282fea5a536510ae86c77ce46f7827687783628e4f2ceb5bf2c41b8cd3c6/behavior
https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsDesktop::Wallpaper
https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.ControlPanelDisplay::CPL_Personalization_NoDesktopBackgroundUI

## False Positives
Administrative scripts that change the desktop background to a company logo or other image.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "Control Panel\Desktop" OR RegistryKeyPath containsCIS "CurrentVersion\Policies\ActiveDesktop" OR RegistryKeyPath containsCIS "CurrentVersion\Policies\System") AND ((RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "NoChangingWallpaper") OR RegistryKeyPath endswithCIS "\Wallpaper" OR (RegistryValue = "2" AND RegistryKeyPath endswithCIS "\WallpaperStyle")) AND (NOT SrcProcImagePath endswithCIS "\svchost.exe")))

```