# proc_creation_win_php_inline_command_execution

## Title
Php Inline Command Execution

## ID
d81871ef-5738-47ab-9797-7a9c90cd4bfb

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-02

## Tags
attack.execution, attack.t1059

## Description
Detects execution of php using the "-r" flag. This is could be used as a way to launch a reverse shell or execute live php code.

## References
https://www.php.net/manual/en/features.commandline.php
https://www.revshells.com/
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -r" AND TgtProcImagePath endswithCIS "\php.exe"))

```