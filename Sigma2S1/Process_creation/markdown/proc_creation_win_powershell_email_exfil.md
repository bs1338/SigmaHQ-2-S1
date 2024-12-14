# proc_creation_win_powershell_email_exfil

## Title
Email Exifiltration Via Powershell

## ID
312d0384-401c-4b8b-abdf-685ffba9a332

## Author
Nasreddine Bencherchali (Nextron Systems),  Azure-Sentinel (idea)

## Date
2022-09-09

## Tags
attack.exfiltration

## Description
Detects email exfiltration via powershell cmdlets

## References
https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
https://github.com/Azure/Azure-Sentinel/blob/7e6aa438e254d468feec061618a7877aa528ee9f/Hunting%20Queries/Microsoft%20365%20Defender/Ransomware/DEV-0270/Email%20data%20exfiltration%20via%20PowerShell.yaml

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Add-PSSnapin" AND TgtProcCmdLine containsCIS "Get-Recipient" AND TgtProcCmdLine containsCIS "-ExpandProperty" AND TgtProcCmdLine containsCIS "EmailAddresses" AND TgtProcCmdLine containsCIS "SmtpAddress" AND TgtProcCmdLine containsCIS "-hidetableheaders") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```