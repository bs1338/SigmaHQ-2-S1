# proc_creation_win_powershell_frombase64string_archive

## Title
Suspicious FromBase64String Usage On Gzip Archive - Process Creation

## ID
d75d6b6b-adb9-48f7-824b-ac2e786efe1f

## Author
frack113

## Date
2022-12-23

## Tags
attack.command-and-control, attack.t1132.001

## Description
Detects attempts of decoding a base64 Gzip archive via PowerShell. This technique is often used as a method to load malicious content into memory afterward.

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=43

## False Positives
Legitimate administrative script

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "FromBase64String" AND TgtProcCmdLine containsCIS "MemoryStream" AND TgtProcCmdLine containsCIS "H4sI"))

```