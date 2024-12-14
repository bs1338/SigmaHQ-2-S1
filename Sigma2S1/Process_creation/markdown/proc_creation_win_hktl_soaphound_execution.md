# proc_creation_win_hktl_soaphound_execution

## Title
HackTool - SOAPHound Execution

## ID
e92a4287-e072-4a40-9739-370c106bb750

## Author
@kostastsale

## Date
2024-01-26

## Tags
attack.discovery, attack.t1087

## Description
Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.


## References
https://github.com/FalconForceTeam/SOAPHound
https://medium.com/falconforce/soaphound-tool-to-collect-active-directory-data-via-adws-165aca78288c

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " --buildcache " OR TgtProcCmdLine containsCIS " --bhdump " OR TgtProcCmdLine containsCIS " --certdump " OR TgtProcCmdLine containsCIS " --dnsdump ") AND (TgtProcCmdLine containsCIS " -c " OR TgtProcCmdLine containsCIS " --cachefilename " OR TgtProcCmdLine containsCIS " -o " OR TgtProcCmdLine containsCIS " --outputdirectory")))

```