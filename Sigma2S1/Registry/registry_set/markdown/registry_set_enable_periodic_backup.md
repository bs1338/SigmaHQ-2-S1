# registry_set_enable_periodic_backup

## Title
Periodic Backup For System Registry Hives Enabled

## ID
973ef012-8f1a-4c40-93b4-7e659a5cd17f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-07-01

## Tags
attack.collection, attack.t1113

## Description
Detects the enabling of the "EnablePeriodicBackup" registry value. Once enabled, The OS will backup System registry hives on restarts to the "C:\Windows\System32\config\RegBack" folder. Windows creates a "RegIdleBackup" task to manage subsequent backups.
Registry backup was a default behavior on Windows and was disabled as of "Windows 10, version 1803".


## References
https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder

## False Positives
Legitimate need for RegBack feature by administrators.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\Control\Session Manager\Configuration Manager\EnablePeriodicBackup"))

```