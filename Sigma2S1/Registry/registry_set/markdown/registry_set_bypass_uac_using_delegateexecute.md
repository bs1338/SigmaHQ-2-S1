# registry_set_bypass_uac_using_delegateexecute

## Title
Bypass UAC Using DelegateExecute

## ID
46dd5308-4572-4d12-aa43-8938f0184d4f

## Author
frack113

## Date
2022-01-05

## Tags
attack.privilege-escalation, attack.defense-evasion, attack.t1548.002

## Description
Bypasses User Account Control using a fileless method

## References
https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-iexecutecommand
https://devblogs.microsoft.com/oldnewthing/20100312-01/?p=14623
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md#atomic-test-7---bypass-uac-using-sdclt-delegateexecute

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "(Empty)" AND RegistryKeyPath endswithCIS "\open\command\DelegateExecute"))

```