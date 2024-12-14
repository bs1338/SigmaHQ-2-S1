# proc_creation_win_susp_obfuscated_ip_download

## Title
Obfuscated IP Download Activity

## ID
cb5a2333-56cf-4562-8fcb-22ba1bca728d

## Author
Florian Roth (Nextron Systems), X__Junior (Nextron Systems)

## Date
2022-08-03

## Tags
attack.discovery

## Description
Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command

## References
https://h.43z.one/ipconverter/
https://twitter.com/Yasser_Elsnbary/status/1553804135354564608
https://twitter.com/fr0s7_/status/1712780207105404948

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Invoke-WebRequest" OR TgtProcCmdLine containsCIS "iwr " OR TgtProcCmdLine containsCIS "wget " OR TgtProcCmdLine containsCIS "curl " OR TgtProcCmdLine containsCIS "DownloadFile" OR TgtProcCmdLine containsCIS "DownloadString") AND ((TgtProcCmdLine containsCIS " 0x" OR TgtProcCmdLine containsCIS "//0x" OR TgtProcCmdLine containsCIS ".0x" OR TgtProcCmdLine containsCIS ".00x") OR (TgtProcCmdLine containsCIS "http://%" AND TgtProcCmdLine containsCIS "%2e") OR (TgtProcCmdLine RegExp "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}" OR TgtProcCmdLine RegExp "https?://[0-9]{1,3}\\.0[0-9]{3,7}" OR TgtProcCmdLine RegExp "https?://0[0-9]{3,11}" OR TgtProcCmdLine RegExp "https?://(0[0-9]{1,11}\\.){3}0[0-9]{1,11}" OR TgtProcCmdLine RegExp "https?://0[0-9]{1,11}" OR TgtProcCmdLine RegExp " [0-7]{7,13}")) AND (NOT TgtProcCmdLine RegExp "https?://((25[0-5]|(2[0-4]|1\\d|[1-9])?\\d)(\\.|\\b)){4}")))

```