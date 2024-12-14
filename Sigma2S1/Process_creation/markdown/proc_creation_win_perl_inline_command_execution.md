# proc_creation_win_perl_inline_command_execution

## Title
Perl Inline Command Execution

## ID
f426547a-e0f7-441a-b63e-854ac5bdf54d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-02

## Tags
attack.execution, attack.t1059

## Description
Detects execution of perl using the "-e"/"-E" flags. This is could be used as a way to launch a reverse shell or execute live perl code.

## References
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
https://www.revshells.com/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -e" AND TgtProcImagePath endswithCIS "\perl.exe"))

```