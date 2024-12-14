# registry_add_persistence_disk_cleanup_handler_entry

## Title
Potential Persistence Via Disk Cleanup Handler - Registry

## ID
d4f4e0be-cf12-439f-9e25-4e2cdcf7df5a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence.
The disk cleanup manager is part of the operating system. It displays the dialog box […]
The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI.
Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications.
 Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler.
Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler.


## References
https://persistence-info.github.io/Data/diskcleanuphandler.html
https://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/

## False Positives
Legitimate new entry added by windows

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((EventType = "CreateKey" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\") AND (NOT (RegistryKeyPath endswithCIS "\Active Setup Temp Folders" OR RegistryKeyPath endswithCIS "\BranchCache" OR RegistryKeyPath endswithCIS "\Content Indexer Cleaner" OR RegistryKeyPath endswithCIS "\D3D Shader Cache" OR RegistryKeyPath endswithCIS "\Delivery Optimization Files" OR RegistryKeyPath endswithCIS "\Device Driver Packages" OR RegistryKeyPath endswithCIS "\Diagnostic Data Viewer database files" OR RegistryKeyPath endswithCIS "\Downloaded Program Files" OR RegistryKeyPath endswithCIS "\DownloadsFolder" OR RegistryKeyPath endswithCIS "\Feedback Hub Archive log files" OR RegistryKeyPath endswithCIS "\Internet Cache Files" OR RegistryKeyPath endswithCIS "\Language Pack" OR RegistryKeyPath endswithCIS "\Microsoft Office Temp Files" OR RegistryKeyPath endswithCIS "\Offline Pages Files" OR RegistryKeyPath endswithCIS "\Old ChkDsk Files" OR RegistryKeyPath endswithCIS "\Previous Installations" OR RegistryKeyPath endswithCIS "\Recycle Bin" OR RegistryKeyPath endswithCIS "\RetailDemo Offline Content" OR RegistryKeyPath endswithCIS "\Setup Log Files" OR RegistryKeyPath endswithCIS "\System error memory dump files" OR RegistryKeyPath endswithCIS "\System error minidump files" OR RegistryKeyPath endswithCIS "\Temporary Files" OR RegistryKeyPath endswithCIS "\Temporary Setup Files" OR RegistryKeyPath endswithCIS "\Temporary Sync Files" OR RegistryKeyPath endswithCIS "\Thumbnail Cache" OR RegistryKeyPath endswithCIS "\Update Cleanup" OR RegistryKeyPath endswithCIS "\Upgrade Discarded Files" OR RegistryKeyPath endswithCIS "\User file versions" OR RegistryKeyPath endswithCIS "\Windows Defender" OR RegistryKeyPath endswithCIS "\Windows Error Reporting Files" OR RegistryKeyPath endswithCIS "\Windows ESD installation files" OR RegistryKeyPath endswithCIS "\Windows Upgrade Log Files"))))

```