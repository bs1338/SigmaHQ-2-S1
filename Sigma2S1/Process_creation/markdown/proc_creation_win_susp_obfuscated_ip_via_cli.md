# proc_creation_win_susp_obfuscated_ip_via_cli

## Title
Obfuscated IP Via CLI

## ID
56d19cb4-6414-4769-9644-1ed35ffbb148

## Author
Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)

## Date
2022-08-03

## Tags
attack.discovery

## Description
Detects usage of an encoded/obfuscated version of an IP address (hex, octal, etc.) via command line

## References
https://h.43z.one/ipconverter/
https://twitter.com/Yasser_Elsnbary/status/1553804135354564608

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\ping.exe" OR TgtProcImagePath endswithCIS "\arp.exe") AND ((TgtProcCmdLine containsCIS " 0x" OR TgtProcCmdLine containsCIS "//0x" OR TgtProcCmdLine containsCIS ".0x" OR TgtProcCmdLine containsCIS ".00x") OR (TgtProcCmdLine containsCIS "http://%" AND TgtProcCmdLine containsCIS "%2e") OR (TgtProcCmdLine RegExp "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}" OR TgtProcCmdLine RegExp "https?://[0-9]{1,3}\\.0[0-9]{3,7}" OR TgtProcCmdLine RegExp "https?://0[0-9]{3,11}" OR TgtProcCmdLine RegExp "https?://(0[0-9]{1,11}\\.){3}0[0-9]{1,11}" OR TgtProcCmdLine RegExp "https?://0[0-9]{1,11}" OR TgtProcCmdLine RegExp " [0-7]{7,13}")) AND (NOT TgtProcCmdLine RegExp "https?://((25[0-5]|(2[0-4]|1\\d|[1-9])?\\d)(\\.|\\b)){4}")))

```