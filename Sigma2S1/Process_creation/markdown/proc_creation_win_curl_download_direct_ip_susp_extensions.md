# proc_creation_win_curl_download_direct_ip_susp_extensions

## Title
Suspicious File Download From IP Via Curl.EXE

## ID
5cb299fc-5fb1-4d07-b989-0644c68b6043

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-27

## Tags
attack.execution

## Description
Detects potentially suspicious file downloads directly from IP addresses using curl.exe

## References
https://labs.withsecure.com/publications/fin7-target-veeam-servers
https://github.com/WithSecureLabs/iocs/blob/344203de742bb7e68bd56618f66d34be95a9f9fc/FIN7VEEAM/iocs.csv
https://github.com/pr0xylife/IcedID/blob/8dd1e218460db4f750d955b4c65b2f918a1db906/icedID_09.28.2023.txt

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS ".bat" OR TgtProcCmdLine endswithCIS ".bat\"" OR TgtProcCmdLine endswithCIS ".dat" OR TgtProcCmdLine endswithCIS ".dat\"" OR TgtProcCmdLine endswithCIS ".dll" OR TgtProcCmdLine endswithCIS ".dll\"" OR TgtProcCmdLine endswithCIS ".exe" OR TgtProcCmdLine endswithCIS ".exe\"" OR TgtProcCmdLine endswithCIS ".gif" OR TgtProcCmdLine endswithCIS ".gif\"" OR TgtProcCmdLine endswithCIS ".hta" OR TgtProcCmdLine endswithCIS ".hta\"" OR TgtProcCmdLine endswithCIS ".jpeg" OR TgtProcCmdLine endswithCIS ".jpeg\"" OR TgtProcCmdLine endswithCIS ".log" OR TgtProcCmdLine endswithCIS ".log\"" OR TgtProcCmdLine endswithCIS ".msi" OR TgtProcCmdLine endswithCIS ".msi\"" OR TgtProcCmdLine endswithCIS ".png" OR TgtProcCmdLine endswithCIS ".png\"" OR TgtProcCmdLine endswithCIS ".ps1" OR TgtProcCmdLine endswithCIS ".ps1\"" OR TgtProcCmdLine endswithCIS ".psm1" OR TgtProcCmdLine endswithCIS ".psm1\"" OR TgtProcCmdLine endswithCIS ".vbe" OR TgtProcCmdLine endswithCIS ".vbe\"" OR TgtProcCmdLine endswithCIS ".vbs" OR TgtProcCmdLine endswithCIS ".vbs\"" OR TgtProcCmdLine endswithCIS ".bat'" OR TgtProcCmdLine endswithCIS ".dat'" OR TgtProcCmdLine endswithCIS ".dll'" OR TgtProcCmdLine endswithCIS ".exe'" OR TgtProcCmdLine endswithCIS ".gif'" OR TgtProcCmdLine endswithCIS ".hta'" OR TgtProcCmdLine endswithCIS ".jpeg'" OR TgtProcCmdLine endswithCIS ".log'" OR TgtProcCmdLine endswithCIS ".msi'" OR TgtProcCmdLine endswithCIS ".png'" OR TgtProcCmdLine endswithCIS ".ps1'" OR TgtProcCmdLine endswithCIS ".psm1'" OR TgtProcCmdLine endswithCIS ".vbe'" OR TgtProcCmdLine endswithCIS ".vbs'") AND (TgtProcCmdLine containsCIS " -O" OR TgtProcCmdLine containsCIS "--remote-name" OR TgtProcCmdLine containsCIS "--output") AND TgtProcCmdLine containsCIS "http" AND TgtProcImagePath endswithCIS "\curl.exe" AND TgtProcCmdLine RegExp "://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"))

```