# file_event_win_advanced_ip_scanner

## Title
Advanced IP Scanner - File Event

## ID
fed85bf9-e075-4280-9159-fbe8a023d6fa

## Author
@ROxPinTeddy

## Date
2020-05-12

## Tags
attack.discovery, attack.t1046

## Description
Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.

## References
https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/
https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html
https://labs.f-secure.com/blog/prelude-to-ransomware-systembc
https://assets.documentcloud.org/documents/20444693/fbi-pin-egregor-ransomware-bc-01062021.pdf
https://thedfirreport.com/2021/01/18/all-that-for-a-coinminer

## False Positives
Legitimate administrative use

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath containsCIS "\AppData\Local\Temp\Advanced IP Scanner 2")

```