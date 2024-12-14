# proc_creation_win_attrib_system_susp_paths

## Title
Set Suspicious Files as System Files Using Attrib.EXE

## ID
efec536f-72e8-4656-8960-5e85d091345b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-28

## Tags
attack.defense-evasion, attack.t1564.001

## Description
Detects the usage of attrib with the "+s" option to set scripts or executables located in suspicious locations as system files to hide them from users and make them unable to be deleted with simple rights. The rule limits the search to specific extensions and directories to avoid FPs


## References
https://app.any.run/tasks/c28cabc8-a19f-40f3-a78b-cae506a5c0d4
https://app.any.run/tasks/cfc8870b-ccd7-4210-88cf-a8087476a6d0
https://unit42.paloaltonetworks.com/unit42-sure-ill-take-new-combojack-malware-alters-clipboards-steal-cryptocurrency/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " +s" AND (TgtProcCmdLine containsCIS ".bat" OR TgtProcCmdLine containsCIS ".dll" OR TgtProcCmdLine containsCIS ".exe" OR TgtProcCmdLine containsCIS ".hta" OR TgtProcCmdLine containsCIS ".ps1" OR TgtProcCmdLine containsCIS ".vbe" OR TgtProcCmdLine containsCIS ".vbs") AND TgtProcImagePath endswithCIS "\attrib.exe" AND (TgtProcCmdLine containsCIS " %" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\AppData\Local\" OR TgtProcCmdLine containsCIS "\ProgramData\" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Windows\Temp\")) AND (NOT (TgtProcCmdLine containsCIS "\Windows\TEMP\" AND TgtProcCmdLine containsCIS ".exe"))))

```