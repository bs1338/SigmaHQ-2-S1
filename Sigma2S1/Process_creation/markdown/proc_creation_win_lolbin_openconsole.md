# proc_creation_win_lolbin_openconsole

## Title
Use of OpenConsole

## ID
814c95cc-8192-4378-a70a-f1aafd877af1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-16

## Tags
attack.execution, attack.t1059

## Description
Detects usage of OpenConsole binary as a LOLBIN to launch other binaries to bypass application Whitelisting

## References
https://twitter.com/nas_bench/status/1537563834478645252

## False Positives
Legitimate use by an administrator

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\OpenConsole.exe" AND (NOT TgtProcImagePath startswithCIS "C:\Program Files\WindowsApps\Microsoft.WindowsTerminal")))

```