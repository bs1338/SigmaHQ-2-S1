# proc_creation_win_verclsid_runs_com

## Title
Verclsid.exe Runs COM Object

## ID
d06be4b9-8045-428b-a567-740a26d9db25

## Author
Victor Sergeev, oscd.community

## Date
2020-10-09

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects when verclsid.exe is used to run COM object via GUID

## References
https://lolbas-project.github.io/lolbas/Binaries/Verclsid/
https://gist.github.com/NickTyrer/0598b60112eaafe6d07789f7964290d5
https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/S" AND TgtProcCmdLine containsCIS "/C") AND TgtProcImagePath endswithCIS "\verclsid.exe"))

```