# proc_creation_win_hktl_bloodhound_sharphound

## Title
HackTool - Bloodhound/Sharphound Execution

## ID
f376c8a7-a2d0-4ddc-aa0c-16c17236d962

## Author
Florian Roth (Nextron Systems)

## Date
2019-12-20

## Tags
attack.discovery, attack.t1087.001, attack.t1087.002, attack.t1482, attack.t1069.001, attack.t1069.002, attack.execution, attack.t1059.001

## Description
Detects command line parameters used by Bloodhound and Sharphound hack tools

## References
https://github.com/BloodHoundAD/BloodHound
https://github.com/BloodHoundAD/SharpHound

## False Positives
Other programs that use these command line option and accepts an 'All' parameter

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -CollectionMethod All " OR TgtProcCmdLine containsCIS " --CollectionMethods Session " OR TgtProcCmdLine containsCIS " --Loop --Loopduration " OR TgtProcCmdLine containsCIS " --PortScanTimeout " OR TgtProcCmdLine containsCIS ".exe -c All -d " OR TgtProcCmdLine containsCIS "Invoke-Bloodhound" OR TgtProcCmdLine containsCIS "Get-BloodHoundData") OR (TgtProcCmdLine containsCIS " -JsonFolder " AND TgtProcCmdLine containsCIS " -ZipFileName ") OR (TgtProcCmdLine containsCIS " DCOnly " AND TgtProcCmdLine containsCIS " --NoSaveCache ") OR (TgtProcDisplayName containsCIS "SharpHound" OR TgtProcDisplayName containsCIS "SharpHound" OR (TgtProcPublisher containsCIS "SpecterOps" OR TgtProcPublisher containsCIS "evil corp") OR (TgtProcImagePath containsCIS "\Bloodhound.exe" OR TgtProcImagePath containsCIS "\SharpHound.exe"))))

```