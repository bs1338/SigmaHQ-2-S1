# proc_creation_win_vaultcmd_list_creds

## Title
Windows Credential Manager Access via VaultCmd

## ID
58f50261-c53b-4c88-bd12-1d71f12eda4c

## Author
frack113

## Date
2022-04-08

## Tags
attack.credential-access, attack.t1555.004

## Description
List credentials currently stored in Windows Credential Manager via the native Windows utility vaultcmd.exe

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555.004/T1555.004.md#atomic-test-1---access-saved-credentials-via-vaultcmd

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/listcreds:" AND TgtProcImagePath endswithCIS "\VaultCmd.exe"))

```