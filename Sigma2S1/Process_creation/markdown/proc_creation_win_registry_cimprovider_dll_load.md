# proc_creation_win_registry_cimprovider_dll_load

## Title
DLL Execution Via Register-cimprovider.exe

## ID
a2910908-e86f-4687-aeba-76a5f996e652

## Author
Ivan Dyachkov, Yulia Fomina, oscd.community

## Date
2020-10-07

## Tags
attack.defense-evasion, attack.t1574

## Description
Detects using register-cimprovider.exe to execute arbitrary dll file.

## References
https://twitter.com/PhilipTsukerman/status/992021361106268161
https://lolbas-project.github.io/lolbas/Binaries/Register-cimprovider/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-path" AND TgtProcCmdLine containsCIS "dll") AND TgtProcImagePath endswithCIS "\register-cimprovider.exe"))

```