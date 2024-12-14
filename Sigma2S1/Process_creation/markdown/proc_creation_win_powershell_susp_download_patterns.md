# proc_creation_win_powershell_susp_download_patterns

## Title
Suspicious PowerShell Download and Execute Pattern

## ID
e6c54d94-498c-4562-a37c-b469d8e9a275

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-28

## Tags
attack.execution, attack.t1059.001

## Description
Detects suspicious PowerShell download patterns that are often used in malicious scripts, stagers or downloaders (make sure that your backend applies the strings case-insensitive)

## References
https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70
https://www.trendmicro.com/en_us/research/22/j/lv-ransomware-exploits-proxyshell-in-attack.html

## False Positives
Software installers that pull packages from remote systems and execute them

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "IEX ((New-Object Net.WebClient).DownloadString" OR TgtProcCmdLine containsCIS "IEX (New-Object Net.WebClient).DownloadString" OR TgtProcCmdLine containsCIS "IEX((New-Object Net.WebClient).DownloadString" OR TgtProcCmdLine containsCIS "IEX(New-Object Net.WebClient).DownloadString" OR TgtProcCmdLine containsCIS " -command (New-Object System.Net.WebClient).DownloadFile(" OR TgtProcCmdLine containsCIS " -c (New-Object System.Net.WebClient).DownloadFile("))

```