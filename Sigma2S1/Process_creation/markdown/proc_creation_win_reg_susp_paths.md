# proc_creation_win_reg_susp_paths

## Title
Reg Add Suspicious Paths

## ID
b7e2a8d4-74bb-4b78-adc9-3f92af2d4829

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1112, attack.t1562.001

## Description
Detects when an adversary uses the reg.exe utility to add or modify new keys or subkeys

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1562.001/T1562.001.md
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

## False Positives
Rare legitimate add to registry via cli (to these locations)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\AppDataLow\Software\Microsoft\" OR TgtProcCmdLine containsCIS "\Policies\Microsoft\Windows\OOBE" OR TgtProcCmdLine containsCIS "\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" OR TgtProcCmdLine containsCIS "\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" OR TgtProcCmdLine containsCIS "\CurrentControlSet\Control\SecurityProviders\WDigest" OR TgtProcCmdLine containsCIS "\Microsoft\Windows Defender\") AND TgtProcImagePath endswithCIS "\reg.exe"))

```