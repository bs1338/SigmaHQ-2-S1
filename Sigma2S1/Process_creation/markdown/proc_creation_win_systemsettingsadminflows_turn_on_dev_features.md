# proc_creation_win_systemsettingsadminflows_turn_on_dev_features

## Title
Potential Signing Bypass Via Windows Developer Features

## ID
a383dec4-deec-4e6e-913b-ed9249670848

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-11

## Tags
attack.defense-evasion

## Description
Detects when a user enable developer features such as "Developer Mode" or "Application Sideloading". Which allows the user to install untrusted packages.

## References
Internal Research
https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "TurnOnDeveloperFeatures" AND TgtProcImagePath endswithCIS "\SystemSettingsAdminFlows.exe" AND (TgtProcCmdLine containsCIS "DeveloperUnlock" OR TgtProcCmdLine containsCIS "EnableSideloading")))

```