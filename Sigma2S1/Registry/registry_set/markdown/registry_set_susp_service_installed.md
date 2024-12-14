# registry_set_susp_service_installed

## Title
Suspicious Service Installed

## ID
f2485272-a156-4773-82d7-1d178bc4905b

## Author
xknow (@xknow_infosec), xorxes (@xor_xes)

## Date
2019-04-08

## Tags
attack.t1562.001, attack.defense-evasion

## Description
Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders.
Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)


## References
https://web.archive.org/web/20200419024230/https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/

## False Positives
Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath In Contains AnyCase ("HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath","HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath")) AND (NOT (RegistryValue containsCIS "\WINDOWS\system32\Drivers\PROCEXP152.SYS" AND (SrcProcImagePath endswithCIS "\procexp64.exe" OR SrcProcImagePath endswithCIS "\procexp.exe" OR SrcProcImagePath endswithCIS "\procmon64.exe" OR SrcProcImagePath endswithCIS "\procmon.exe" OR SrcProcImagePath endswithCIS "\handle.exe" OR SrcProcImagePath endswithCIS "\handle64.exe")))))

```