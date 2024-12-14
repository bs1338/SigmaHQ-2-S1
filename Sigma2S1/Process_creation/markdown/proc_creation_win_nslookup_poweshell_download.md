# proc_creation_win_nslookup_poweshell_download

## Title
Nslookup PowerShell Download Cradle - ProcessCreation

## ID
1b3b01c7-84e9-4072-86e5-fc285a41ff23

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-05

## Tags
attack.defense-evasion

## Description
Detects suspicious powershell download cradle using nslookup. This cradle uses nslookup to extract payloads from DNS records

## References
https://twitter.com/Alh4zr3d/status/1566489367232651264

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -q=txt " OR TgtProcCmdLine containsCIS " -querytype=txt ") AND (SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe")) AND TgtProcImagePath containsCIS "\nslookup.exe"))

```