# proc_creation_win_cmd_stdin_redirect

## Title
Read Contents From Stdin Via Cmd.EXE

## ID
241e802a-b65e-484f-88cd-c2dc10f9206d

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-07

## Tags
attack.execution, attack.t1059.003

## Description
Detect the use of "<" to read and potentially execute a file via cmd.exe

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1059.003/T1059.003.md
https://web.archive.org/web/20220306121156/https://www.x86matthew.com/view_post?id=ntdll_pipe

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "<" AND TgtProcImagePath endswithCIS "\cmd.exe"))

```