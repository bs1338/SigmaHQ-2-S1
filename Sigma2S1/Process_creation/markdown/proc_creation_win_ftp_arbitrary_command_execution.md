# proc_creation_win_ftp_arbitrary_command_execution

## Title
Potential Arbitrary Command Execution Via FTP.EXE

## ID
06b401f4-107c-4ff9-947f-9ec1e7649f1e

## Author
Victor Sergeev, oscd.community

## Date
2020-10-09

## Tags
attack.execution, attack.t1059, attack.defense-evasion, attack.t1202

## Description
Detects execution of "ftp.exe" script with the "-s" or "/s" flag and any child processes ran by "ftp.exe".

## References
https://lolbas-project.github.io/lolbas/Binaries/Ftp/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\ftp.exe" OR ((TgtProcCmdLine containsCIS "-s:" OR TgtProcCmdLine containsCIS "/s:" OR TgtProcCmdLine containsCIS "â€“s:" OR TgtProcCmdLine containsCIS "â€”s:" OR TgtProcCmdLine containsCIS "â€•s:") AND TgtProcImagePath endswithCIS "\ftp.exe")))

```