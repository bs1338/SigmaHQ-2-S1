# file_event_win_susp_procexplorer_driver_created_in_tmp_folder

## Title
Suspicious PROCEXP152.sys File Created In TMP

## ID
3da70954-0f2c-4103-adff-b7440368f50e

## Author
xknow (@xknow_infosec), xorxes (@xor_xes)

## Date
2019-04-08

## Tags
attack.t1562.001, attack.defense-evasion

## Description
Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder.
This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.


## References
https://web.archive.org/web/20230331181619/https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/

## False Positives
Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\AppData\Local\Temp\" AND TgtFilePath endswithCIS "PROCEXP152.sys") AND (NOT (SrcProcImagePath containsCIS "\procexp64.exe" OR SrcProcImagePath containsCIS "\procexp.exe" OR SrcProcImagePath containsCIS "\procmon64.exe" OR SrcProcImagePath containsCIS "\procmon.exe"))))

```