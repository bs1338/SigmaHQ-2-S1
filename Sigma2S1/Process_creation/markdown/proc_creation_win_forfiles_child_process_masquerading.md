# proc_creation_win_forfiles_child_process_masquerading

## Title
Forfiles.EXE Child Process Masquerading

## ID
f53714ec-5077-420e-ad20-907ff9bb2958

## Author
Nasreddine Bencherchali (Nextron Systems), Anish Bogati

## Date
2024-01-05

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects the execution of "forfiles" from a non-default location, in order to potentially spawn a custom "cmd.exe" from the current working directory.


## References
https://www.hexacorn.com/blog/2023/12/31/1-little-known-secret-of-forfiles-exe/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine startswithCIS "/c echo \"" AND TgtProcImagePath endswithCIS "\cmd.exe" AND (SrcProcCmdLine endswithCIS ".exe" OR SrcProcCmdLine endswithCIS ".exe\"")) AND (NOT ((TgtProcImagePath containsCIS ":\Windows\System32\" OR TgtProcImagePath containsCIS ":\Windows\SysWOW64\") AND TgtProcImagePath endswithCIS "\cmd.exe" AND (SrcProcImagePath containsCIS ":\Windows\System32\" OR SrcProcImagePath containsCIS ":\Windows\SysWOW64\") AND SrcProcImagePath endswithCIS "\forfiles.exe"))))

```