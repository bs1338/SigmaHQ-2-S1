# proc_creation_win_powershell_amsi_null_bits_bypass

## Title
Potential AMSI Bypass Using NULL Bits

## ID
92a974db-ab84-457f-9ec0-55db83d7a825

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-04

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects usage of special strings/null bits in order to potentially bypass AMSI functionalities

## References
https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#amsi-bypass-using-null-bits-satoshi

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "if(0){{{0}}}' -f $(0 -as [char]) +" OR TgtProcCmdLine containsCIS "#<NULL>"))

```