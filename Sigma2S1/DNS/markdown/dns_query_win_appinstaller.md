# dns_query_win_appinstaller

## Title
AppX Package Installation Attempts Via AppInstaller.EXE

## ID
7cff77e1-9663-46a3-8260-17f2e1aa9d0a

## Author
frack113

## Date
2021-11-24

## Tags
attack.command-and-control, attack.t1105

## Description
Detects DNS queries made by "AppInstaller.EXE". The AppInstaller is the default handler for the "ms-appinstaller" URI. It attempts to load/install a package from the referenced URL


## References
https://twitter.com/notwhickey/status/1333900137232523264
https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\AppInstaller.exe" AND SrcProcImagePath startswithCIS "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_"))

```