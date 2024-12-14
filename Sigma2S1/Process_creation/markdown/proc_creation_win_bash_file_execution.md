# proc_creation_win_bash_file_execution

## Title
Indirect Command Execution From Script File Via Bash.EXE

## ID
2d22a514-e024-4428-9dba-41505bd63a5b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-15

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects execution of Microsoft bash launcher without any flags to execute the content of a bash script directly.
This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.


## References
https://lolbas-project.github.io/lolbas/Binaries/Bash/
https://linux.die.net/man/1/bash
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS ":\Windows\System32\bash.exe" OR TgtProcImagePath endswithCIS ":\Windows\SysWOW64\bash.exe") AND (NOT ((TgtProcCmdLine containsCIS "bash.exe -" OR TgtProcCmdLine containsCIS "bash -") OR TgtProcCmdLine = "" OR TgtProcCmdLine IS NOT EMPTY OR (TgtProcCmdLine In Contains AnyCase ("bash.exe","bash"))))))

```