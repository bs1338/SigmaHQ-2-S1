# registry_set_lolbin_onedrivestandaloneupdater

## Title
Lolbas OneDriveStandaloneUpdater.exe Proxy Download

## ID
3aff0be0-7802-4a7e-a4fa-c60c74bc5e1d

## Author
frack113

## Date
2022-05-28

## Tags
attack.command-and-control, attack.t1105

## Description
Detects setting a custom URL for OneDriveStandaloneUpdater.exe to download a file from the Internet without executing any
anomalous executables with suspicious arguments. The downloaded file will be in C:\Users\redacted\AppData\Local\Microsoft\OneDrive\StandaloneUpdaterreSignInSettingsConfig.json


## References
https://lolbas-project.github.io/lolbas/Binaries/OneDriveStandaloneUpdater/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\OneDrive\UpdateOfficeConfig\UpdateRingSettingURLFromOC")

```