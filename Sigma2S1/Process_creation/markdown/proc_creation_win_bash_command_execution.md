# proc_creation_win_bash_command_execution

## Title
Indirect Inline Command Execution Via Bash.EXE

## ID
5edc2273-c26f-406c-83f3-f4d948e740dd

## Author
frack113

## Date
2021-11-24

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects execution of Microsoft bash launcher with the "-c" flag.
 This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash.


## References
https://lolbas-project.github.io/lolbas/Binaries/Bash/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -c " AND (TgtProcImagePath endswithCIS ":\Windows\System32\bash.exe" OR TgtProcImagePath endswithCIS ":\Windows\SysWOW64\bash.exe")))

```