# proc_creation_win_hktl_htran_or_natbypass

## Title
HackTool - Htran/NATBypass Execution

## ID
f5e3b62f-e577-4e59-931e-0a15b2b94e1e

## Author
Florian Roth (Nextron Systems)

## Date
2022-12-27

## Tags
attack.command-and-control, attack.t1090, attack.s0040

## Description
Detects executable names or flags used by Htran or Htran-like tools (e.g. NATBypass)

## References
https://github.com/HiwinCN/HTran
https://github.com/cw1997/NATBypass

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".exe -tran " OR TgtProcCmdLine containsCIS ".exe -slave ") OR (TgtProcImagePath endswithCIS "\htran.exe" OR TgtProcImagePath endswithCIS "\lcx.exe")))

```