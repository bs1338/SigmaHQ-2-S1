# proc_creation_win_reg_desktop_background_change

## Title
Potentially Suspicious Desktop Background Change Using Reg.EXE

## ID
8cbc9475-8d05-4e27-9c32-df960716c701

## Author
Stephen Lincoln @slincoln-aiq (AttackIQ)

## Date
2023-12-21

## Tags
attack.defense-evasion, attack.impact, attack.t1112, attack.t1491.001

## Description
Detects the execution of "reg.exe" to alter registry keys that would replace the user's desktop background.
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
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "add" AND TgtProcImagePath endswithCIS "\reg.exe") AND (TgtProcCmdLine containsCIS "Control Panel\Desktop" OR TgtProcCmdLine containsCIS "CurrentVersion\Policies\ActiveDesktop" OR TgtProcCmdLine containsCIS "CurrentVersion\Policies\System") AND ((TgtProcCmdLine containsCIS "/v NoChangingWallpaper" AND TgtProcCmdLine containsCIS "/d 1") OR (TgtProcCmdLine containsCIS "/v Wallpaper" AND TgtProcCmdLine containsCIS "/t REG_SZ") OR (TgtProcCmdLine containsCIS "/v WallpaperStyle" AND TgtProcCmdLine containsCIS "/d 2"))))

```