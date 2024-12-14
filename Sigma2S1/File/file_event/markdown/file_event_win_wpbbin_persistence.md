# file_event_win_wpbbin_persistence

## Title
UEFI Persistence Via Wpbbin - FileCreation

## ID
e94b9ddc-eec5-4bb8-8a58-b9dc5f4e185f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-18

## Tags
attack.persistence, attack.defense-evasion, attack.t1542.001

## Description
Detects creation of a file named "wpbbin" in the "%systemroot%\system32\" directory. Which could be indicative of UEFI based persistence method

## References
https://grzegorztworek.medium.com/using-uefi-to-inject-executable-files-into-bitlocker-protected-drives-8ff4ca59c94c
https://persistence-info.github.io/Data/wpbbin.html

## False Positives
Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath = "C:\Windows\System32\wpbbin.exe")

```