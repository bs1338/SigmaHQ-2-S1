# file_delete_win_zone_identifier_ads_uncommon

## Title
ADS Zone.Identifier Deleted By Uncommon Application

## ID
3109530e-ab47-4cc6-a953-cac5ebcc93ae

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-09-04

## Tags
attack.defense-evasion, attack.t1070.004

## Description
Detects the deletion of the "Zone.Identifier" ADS by an uncommon process. Attackers can leverage this in order to bypass security restrictions that make use of the ADS such as Microsoft Office apps.

## References
https://securityliterate.com/how-malware-abuses-the-zone-identifier-to-circumvent-detection-and-analysis/
Internal Research

## False Positives
Other third party applications not listed.

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ":Zone.Identifier" AND (NOT (SrcProcImagePath In Contains AnyCase ("C:\Program Files\PowerShell\7-preview\pwsh.exe","C:\Program Files\PowerShell\7\pwsh.exe","C:\Windows\explorer.exe","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","C:\Windows\SysWOW64\explorer.exe","C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"))) AND (NOT ((SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Google\Chrome\Application\chrome.exe","C:\Program Files\Google\Chrome\Application\chrome.exe")) OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Mozilla Firefox\firefox.exe","C:\Program Files\Mozilla Firefox\firefox.exe"))))))

```