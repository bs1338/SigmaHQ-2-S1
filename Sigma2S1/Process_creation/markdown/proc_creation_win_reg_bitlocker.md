# proc_creation_win_reg_bitlocker

## Title
Suspicious Reg Add BitLocker

## ID
0e0255bf-2548-47b8-9582-c0955c9283f5

## Author
frack113

## Date
2021-11-15

## Tags
attack.impact, attack.t1486

## Description
Detects suspicious addition to BitLocker related registry keys via the reg.exe utility

## References
https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "EnableBDEWithNoTPM" OR TgtProcCmdLine containsCIS "UseAdvancedStartup" OR TgtProcCmdLine containsCIS "UseTPM" OR TgtProcCmdLine containsCIS "UseTPMKey" OR TgtProcCmdLine containsCIS "UseTPMKeyPIN" OR TgtProcCmdLine containsCIS "RecoveryKeyMessageSource" OR TgtProcCmdLine containsCIS "UseTPMPIN" OR TgtProcCmdLine containsCIS "RecoveryKeyMessage") AND (TgtProcCmdLine containsCIS "REG" AND TgtProcCmdLine containsCIS "ADD" AND TgtProcCmdLine containsCIS "\SOFTWARE\Policies\Microsoft\FVE" AND TgtProcCmdLine containsCIS "/v" AND TgtProcCmdLine containsCIS "/f")))

```