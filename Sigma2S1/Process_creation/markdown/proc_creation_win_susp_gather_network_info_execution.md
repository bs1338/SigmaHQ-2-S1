# proc_creation_win_susp_gather_network_info_execution

## Title
Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS

## ID
07aa184a-870d-413d-893a-157f317f6f58

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-08

## Tags
attack.discovery, attack.execution, attack.t1615, attack.t1059.005

## Description
Detects execution of the built-in script located in "C:\Windows\System32\gatherNetworkInfo.vbs". Which can be used to gather information about the target machine

## References
https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "gatherNetworkInfo.vbs" AND (NOT (TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\wscript.exe"))))

```