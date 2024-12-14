# proc_creation_win_hktl_zipexec

## Title
Suspicious ZipExec Execution

## ID
90dcf730-1b71-4ae7-9ffc-6fcf62bd0132

## Author
frack113

## Date
2021-11-07

## Tags
attack.execution, attack.defense-evasion, attack.t1218, attack.t1202

## Description
ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.

## References
https://twitter.com/SBousseaden/status/1451237393017839616
https://github.com/Tylous/ZipExec

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/generic:Microsoft_Windows_Shell_ZipFolder:filename=" AND TgtProcCmdLine containsCIS ".zip" AND TgtProcCmdLine containsCIS "/pass:" AND TgtProcCmdLine containsCIS "/user:") OR (TgtProcCmdLine containsCIS "/delete" AND TgtProcCmdLine containsCIS "Microsoft_Windows_Shell_ZipFolder:filename=" AND TgtProcCmdLine containsCIS ".zip")))

```