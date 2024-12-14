# proc_creation_win_msiexec_embedding

## Title
Suspicious MsiExec Embedding Parent

## ID
4a2a2c3e-209f-4d01-b513-4155a540b469

## Author
frack113

## Date
2022-04-16

## Tags
attack.t1218.007, attack.defense-evasion

## Description
Adversaries may abuse msiexec.exe to proxy the execution of malicious payloads

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\cmd.exe") AND (SrcProcCmdLine containsCIS "MsiExec.exe" AND SrcProcCmdLine containsCIS "-Embedding ")) AND (NOT ((TgtProcCmdLine containsCIS "C:\Program Files\SplunkUniversalForwarder\bin\" AND TgtProcImagePath endswithCIS ":\Windows\System32\cmd.exe") OR (TgtProcCmdLine containsCIS "\DismFoDInstall.cmd" OR (SrcProcCmdLine containsCIS "\MsiExec.exe -Embedding " AND SrcProcCmdLine containsCIS "Global\MSI0000"))))))

```