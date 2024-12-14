# proc_creation_win_regedit_export_keys

## Title
Exports Registry Key To a File

## ID
f0e53e89-8d22-46ea-9db5-9d4796ee2f8a

## Author
Oddvar Moe, Sander Wiebing, oscd.community

## Date
2020-10-07

## Tags
attack.exfiltration, attack.t1012

## Description
Detects the export of the target Registry key to a file.

## References
https://lolbas-project.github.io/lolbas/Binaries/Regedit/
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f

## False Positives
Legitimate export of keys

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -E " OR TgtProcCmdLine containsCIS " /E " OR TgtProcCmdLine containsCIS " â€“E " OR TgtProcCmdLine containsCIS " â€”E " OR TgtProcCmdLine containsCIS " â€•E ") AND TgtProcImagePath endswithCIS "\regedit.exe") AND (NOT ((TgtProcCmdLine containsCIS "hklm" OR TgtProcCmdLine containsCIS "hkey_local_machine") AND (TgtProcCmdLine endswithCIS "\system" OR TgtProcCmdLine endswithCIS "\sam" OR TgtProcCmdLine endswithCIS "\security")))))

```