# proc_creation_win_netsh_helper_dll_persistence

## Title
Potential Persistence Via Netsh Helper DLL

## ID
56321594-9087-49d9-bf10-524fe8479452

## Author
Victor Sergeev, oscd.community

## Date
2019-10-25

## Tags
attack.privilege-escalation, attack.persistence, attack.t1546.007, attack.s0108

## Description
Detects the execution of netsh with "add helper" flag in order to add a custom helper DLL. This technique can be abused to add a malicious helper DLL that can be used as a persistence proxy that gets called when netsh.exe is executed.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.007/T1546.007.md
https://github.com/outflanknl/NetshHelperBeacon
https://web.archive.org/web/20160928212230/https://www.adaptforward.com/2016/09/using-netshell-to-execute-evil-dlls-and-persist-on-a-host/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "helper") AND TgtProcImagePath endswithCIS "\netsh.exe"))

```