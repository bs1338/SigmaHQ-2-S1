# proc_creation_win_hktl_crackmapexec_patterns

## Title
HackTool - CrackMapExec Process Patterns

## ID
f26307d8-14cd-47e3-a26b-4b4769f24af6

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-12

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects suspicious process patterns found in logs when CrackMapExec is used

## References
https://mpgn.gitbook.io/crackmapexec/smb-protocol/obtaining-credentials/dump-lsass

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "cmd.exe /c " OR TgtProcCmdLine containsCIS "cmd.exe /r " OR TgtProcCmdLine containsCIS "cmd.exe /k " OR TgtProcCmdLine containsCIS "cmd /c " OR TgtProcCmdLine containsCIS "cmd /r " OR TgtProcCmdLine containsCIS "cmd /k ") AND (TgtProcCmdLine containsCIS "tasklist /fi " AND TgtProcCmdLine containsCIS "Imagename eq lsass.exe") AND (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI")) OR (TgtProcCmdLine containsCIS "do rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump" AND TgtProcCmdLine containsCIS "\Windows\Temp\" AND TgtProcCmdLine containsCIS " full" AND TgtProcCmdLine containsCIS "%%B") OR (TgtProcCmdLine containsCIS "tasklist /v /fo csv" AND TgtProcCmdLine containsCIS "findstr /i \"lsass\"")))

```