# proc_creation_win_wpbbin_potential_persistence

## Title
UEFI Persistence Via Wpbbin - ProcessCreation

## ID
4abc0ec4-db5a-412f-9632-26659cddf145

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-18

## Tags
attack.persistence, attack.defense-evasion, attack.t1542.001

## Description
Detects execution of the binary "wpbbin" which is used as part of the UEFI based persistence method described in the reference section

## References
https://grzegorztworek.medium.com/using-uefi-to-inject-executable-files-into-bitlocker-protected-drives-8ff4ca59c94c
https://persistence-info.github.io/Data/wpbbin.html

## False Positives
Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath = "C:\Windows\System32\wpbbin.exe")

```