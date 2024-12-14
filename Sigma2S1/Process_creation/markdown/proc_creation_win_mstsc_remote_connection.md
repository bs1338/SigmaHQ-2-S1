# proc_creation_win_mstsc_remote_connection

## Title
New Remote Desktop Connection Initiated Via Mstsc.EXE

## ID
954f0af7-62dd-418f-b3df-a84bc2c7a774

## Author
frack113

## Date
2022-01-07

## Tags
attack.lateral-movement, attack.t1021.001

## Description
Detects the usage of "mstsc.exe" with the "/v" flag to initiate a connection to a remote server.
Adversaries may use valid accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.001/T1021.001.md#t1021001---remote-desktop-protocol
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc

## False Positives
WSL (Windows Sub System For Linux)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -v:" OR TgtProcCmdLine containsCIS " /v:" OR TgtProcCmdLine containsCIS " â€“v:" OR TgtProcCmdLine containsCIS " â€”v:" OR TgtProcCmdLine containsCIS " â€•v:") AND TgtProcImagePath endswithCIS "\mstsc.exe") AND (NOT (TgtProcCmdLine containsCIS "C:\ProgramData\Microsoft\WSL\wslg.rdp" AND SrcProcImagePath = "C:\Windows\System32\lxss\wslhost.exe"))))

```