# proc_creation_win_cmdkey_adding_generic_creds

## Title
New Generic Credentials Added Via Cmdkey.EXE

## ID
b1ec66c6-f4d1-4b5c-96dd-af28ccae7727

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-03

## Tags
attack.credential-access, attack.t1003.005

## Description
Detects usage of "cmdkey.exe" to add generic credentials.
As an example, this can be used before connecting to an RDP session via command line interface.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.001/T1021.001.md#t1021001---remote-desktop-protocol

## False Positives
Legitimate usage for administration purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -g" OR TgtProcCmdLine containsCIS " /g" OR TgtProcCmdLine containsCIS " â€“g" OR TgtProcCmdLine containsCIS " â€”g" OR TgtProcCmdLine containsCIS " â€•g") AND (TgtProcCmdLine containsCIS " -p" OR TgtProcCmdLine containsCIS " /p" OR TgtProcCmdLine containsCIS " â€“p" OR TgtProcCmdLine containsCIS " â€”p" OR TgtProcCmdLine containsCIS " â€•p") AND (TgtProcCmdLine containsCIS " -u" OR TgtProcCmdLine containsCIS " /u" OR TgtProcCmdLine containsCIS " â€“u" OR TgtProcCmdLine containsCIS " â€”u" OR TgtProcCmdLine containsCIS " â€•u") AND TgtProcImagePath endswithCIS "\cmdkey.exe"))

```