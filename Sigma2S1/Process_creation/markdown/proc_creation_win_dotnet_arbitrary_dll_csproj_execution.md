# proc_creation_win_dotnet_arbitrary_dll_csproj_execution

## Title
Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE

## ID
d80d5c81-04ba-45b4-84e4-92eba40e0ad3

## Author
Beyu Denis, oscd.community

## Date
2020-10-18

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of arbitrary DLLs or unsigned code via a ".csproj" files via Dotnet.EXE.

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Dotnet/
https://twitter.com/_felamos/status/1204705548668555264
https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/

## False Positives
Legitimate administrator usage

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS ".csproj" OR TgtProcCmdLine endswithCIS ".csproj\"" OR TgtProcCmdLine endswithCIS ".dll" OR TgtProcCmdLine endswithCIS ".dll\"" OR TgtProcCmdLine endswithCIS ".csproj'" OR TgtProcCmdLine endswithCIS ".dll'") AND TgtProcImagePath endswithCIS "\dotnet.exe"))

```