# registry_set_wab_dllpath_reg_change

## Title
Execution DLL of Choice Using WAB.EXE

## ID
fc014922-5def-4da9-a0fc-28c973f41bfb

## Author
oscd.community, Natalia Shornikova

## Date
2020-10-13

## Tags
attack.defense-evasion, attack.t1218

## Description
This rule detects that the path to the DLL written in the registry is different from the default one. Launched WAB.exe tries to load the DLL from Registry.

## References
https://github.com/LOLBAS-Project/LOLBAS/blob/8283d8d91552213ded165fd36deb6cb9534cb443/yml/OSBinaries/Wab.yml
https://twitter.com/Hexacorn/status/991447379864932352
http://www.hexacorn.com/blog/2018/05/01/wab-exe-as-a-lolbin/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "\Software\Microsoft\WAB\DLLPath" AND (NOT RegistryValue = "%CommonProgramFiles%\System\wab32.dll")))

```