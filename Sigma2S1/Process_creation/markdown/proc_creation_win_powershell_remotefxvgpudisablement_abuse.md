# proc_creation_win_powershell_remotefxvgpudisablement_abuse

## Title
RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses

## ID
a6fc3c46-23b8-4996-9ea2-573f4c4d88c5

## Author
frack113

## Date
2021-07-13

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects calls to the AtomicTestHarnesses "Invoke-ATHRemoteFXvGPUDisablementCommand" which is designed to abuse the "RemoteFXvGPUDisablement.exe" binary to run custom PowerShell code via module load-order hijacking.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
https://github.com/redcanaryco/AtomicTestHarnesses/blob/7e1e4da116801e3d6fcc6bedb207064577e40572/TestHarnesses/T1218_SignedBinaryProxyExecution/InvokeRemoteFXvGPUDisablementCommand.ps1

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Invoke-ATHRemoteFXvGPUDisablementCommand" OR TgtProcCmdLine containsCIS "Invoke-ATHRemoteFXvGPUDisableme"))

```