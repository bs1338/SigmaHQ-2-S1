# proc_creation_win_lolbin_gather_network_info

## Title
Potential Reconnaissance Activity Via GatherNetworkInfo.VBS

## ID
575dce0c-8139-4e30-9295-1ee75969f7fe

## Author
blueteamer8699

## Date
2022-01-03

## Tags
attack.discovery, attack.execution, attack.t1615, attack.t1059.005

## Description
Detects execution of the built-in script located in "C:\Windows\System32\gatherNetworkInfo.vbs". Which can be used to gather information about the target machine

## References
https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "gatherNetworkInfo.vbs" AND (TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\wscript.exe")))

```