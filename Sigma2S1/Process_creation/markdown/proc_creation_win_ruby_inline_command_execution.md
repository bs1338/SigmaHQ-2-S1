# proc_creation_win_ruby_inline_command_execution

## Title
Ruby Inline Command Execution

## ID
20a5ffa1-3848-4584-b6f8-c7c7fd9f69c8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-02

## Tags
attack.execution, attack.t1059

## Description
Detects execution of ruby using the "-e" flag. This is could be used as a way to launch a reverse shell or execute live ruby code.

## References
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
https://www.revshells.com/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -e" AND TgtProcImagePath endswithCIS "\ruby.exe"))

```