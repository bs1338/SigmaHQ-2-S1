# proc_creation_win_powershell_zip_compress

## Title
Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet

## ID
85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98

## Author
Nasreddine Bencherchali (Nextron Systems), frack113

## Date
2021-07-20

## Tags
attack.collection, attack.t1074.001

## Description
Detects PowerShell scripts that make use of the "Compress-Archive" Cmdlet in order to compress folders and files where the output is stored in a potentially suspicious location that is used often by malware for exfiltration.
 An adversary might compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1074.001/T1074.001.md
https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine = "*Compress-Archive -Path*-DestinationPath $env:TEMP*" OR TgtProcCmdLine = "*Compress-Archive -Path*-DestinationPath*\AppData\Local\Temp\*" OR TgtProcCmdLine = "*Compress-Archive -Path*-DestinationPath*:\Windows\Temp\*"))

```