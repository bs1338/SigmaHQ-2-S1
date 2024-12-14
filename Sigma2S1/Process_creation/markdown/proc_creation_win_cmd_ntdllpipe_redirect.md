# proc_creation_win_cmd_ntdllpipe_redirect

## Title
NtdllPipe Like Activity Execution

## ID
bbc865e4-7fcd-45a6-8ff1-95ced28ec5b2

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-05

## Tags
attack.defense-evasion

## Description
Detects command that type the content of ntdll.dll to a different file or a pipe in order to evade AV / EDR detection. As seen being used in the POC NtdllPipe

## References
https://web.archive.org/web/20220306121156/https://www.x86matthew.com/view_post?id=ntdll_pipe

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "type %windir%\system32\ntdll.dll" OR TgtProcCmdLine containsCIS "type %systemroot%\system32\ntdll.dll" OR TgtProcCmdLine containsCIS "type c:\windows\system32\ntdll.dll" OR TgtProcCmdLine containsCIS "\ntdll.dll > \\.\pipe\"))

```