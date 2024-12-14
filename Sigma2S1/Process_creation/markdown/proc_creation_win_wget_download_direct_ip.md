# proc_creation_win_wget_download_direct_ip

## Title
Suspicious File Download From IP Via Wget.EXE

## ID
17f0c0a8-8bd5-4ee0-8c5f-a342c0199f35

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-27

## Tags
attack.execution

## Description
Detects potentially suspicious file downloads directly from IP addresses using Wget.exe

## References
https://www.gnu.org/software/wget/manual/wget.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS ".ps1" OR TgtProcCmdLine endswithCIS ".ps1'" OR TgtProcCmdLine endswithCIS ".ps1\"" OR TgtProcCmdLine endswithCIS ".dat" OR TgtProcCmdLine endswithCIS ".dat'" OR TgtProcCmdLine endswithCIS ".dat\"" OR TgtProcCmdLine endswithCIS ".msi" OR TgtProcCmdLine endswithCIS ".msi'" OR TgtProcCmdLine endswithCIS ".msi\"" OR TgtProcCmdLine endswithCIS ".bat" OR TgtProcCmdLine endswithCIS ".bat'" OR TgtProcCmdLine endswithCIS ".bat\"" OR TgtProcCmdLine endswithCIS ".exe" OR TgtProcCmdLine endswithCIS ".exe'" OR TgtProcCmdLine endswithCIS ".exe\"" OR TgtProcCmdLine endswithCIS ".vbs" OR TgtProcCmdLine endswithCIS ".vbs'" OR TgtProcCmdLine endswithCIS ".vbs\"" OR TgtProcCmdLine endswithCIS ".vbe" OR TgtProcCmdLine endswithCIS ".vbe'" OR TgtProcCmdLine endswithCIS ".vbe\"" OR TgtProcCmdLine endswithCIS ".hta" OR TgtProcCmdLine endswithCIS ".hta'" OR TgtProcCmdLine endswithCIS ".hta\"" OR TgtProcCmdLine endswithCIS ".dll" OR TgtProcCmdLine endswithCIS ".dll'" OR TgtProcCmdLine endswithCIS ".dll\"" OR TgtProcCmdLine endswithCIS ".psm1" OR TgtProcCmdLine endswithCIS ".psm1'" OR TgtProcCmdLine endswithCIS ".psm1\"") AND (TgtProcCmdLine RegExp "\\s-O\\s" OR TgtProcCmdLine containsCIS "--output-document") AND TgtProcCmdLine containsCIS "http" AND TgtProcImagePath endswithCIS "\wget.exe" AND TgtProcCmdLine RegExp "://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"))

```