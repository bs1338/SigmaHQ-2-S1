# registry_set_winlogon_notify_key

## Title
Winlogon Notify Key Logon Persistence

## ID
bbf59793-6efb-4fa1-95ca-a7d288e52c88

## Author
frack113

## Date
2021-12-30

## Tags
attack.persistence, attack.t1547.004

## Description
Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in.
Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.004/T1547.004.md#atomic-test-3---winlogon-notify-key-logon-persistence---powershell

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue endswithCIS ".dll" AND RegistryKeyPath endswithCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\logon"))

```