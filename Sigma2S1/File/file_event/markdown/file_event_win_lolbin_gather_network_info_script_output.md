# file_event_win_lolbin_gather_network_info_script_output

## Title
GatherNetworkInfo.VBS Reconnaissance Script Output

## ID
f92a6f1e-a512-4a15-9735-da09e78d7273

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-08

## Tags
attack.discovery

## Description
Detects creation of files which are the results of executing the built-in reconnaissance script "C:\Windows\System32\gatherNetworkInfo.vbs".

## References
https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\Hotfixinfo.txt" OR TgtFilePath endswithCIS "\netiostate.txt" OR TgtFilePath endswithCIS "\sysportslog.txt" OR TgtFilePath endswithCIS "\VmSwitchLog.evtx") AND TgtFilePath startswithCIS "C:\Windows\System32\config"))

```