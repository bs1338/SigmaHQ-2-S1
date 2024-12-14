# registry_set_disk_cleanup_handler_autorun_persistence

## Title
Persistence Via Disk Cleanup Handler - Autorun

## ID
d4e2745c-f0c6-4bde-a3ab-b553b3f693cc

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence via autorun.
The disk cleanup manager is part of the operating system.
It displays the dialog box […] The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI.
Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications.
 Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler.
Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler.


## References
https://persistence-info.github.io/Data/diskcleanuphandler.html
https://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\" AND ((RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath containsCIS "\Autorun") OR ((RegistryValue containsCIS "cmd" OR RegistryValue containsCIS "powershell" OR RegistryValue containsCIS "rundll32" OR RegistryValue containsCIS "mshta" OR RegistryValue containsCIS "cscript" OR RegistryValue containsCIS "wscript" OR RegistryValue containsCIS "wsl" OR RegistryValue containsCIS "\Users\Public\" OR RegistryValue containsCIS "\Windows\TEMP\" OR RegistryValue containsCIS "\Microsoft\Windows\Start Menu\Programs\Startup\") AND (RegistryKeyPath containsCIS "\CleanupString" OR RegistryKeyPath containsCIS "\PreCleanupString")))))

```