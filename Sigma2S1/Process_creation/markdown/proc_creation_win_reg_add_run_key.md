# proc_creation_win_reg_add_run_key

## Title
Potential Persistence Attempt Via Run Keys Using Reg.EXE

## ID
de587dce-915e-4218-aac4-835ca6af6f70

## Author
Florian Roth (Nextron Systems)

## Date
2021-06-28

## Tags
attack.persistence, attack.t1547.001

## Description
Detects suspicious command line reg.exe tool adding key to RUN key in Registry

## References
https://app.any.run/tasks/9c0f37bc-867a-4314-b685-e101566766d7/
https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys

## False Positives
Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reasons.
Legitimate administrator sets up autorun keys for legitimate reasons.
Discord

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "reg" AND TgtProcCmdLine containsCIS " ADD " AND TgtProcCmdLine containsCIS "Software\Microsoft\Windows\CurrentVersion\Run"))

```