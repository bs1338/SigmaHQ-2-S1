# proc_creation_win_conhost_legacy_option

## Title
Suspicious High IntegrityLevel Conhost Legacy Option

## ID
3037d961-21e9-4732-b27a-637bcc7bf539

## Author
frack113

## Date
2022-12-09

## Tags
attack.defense-evasion, attack.t1202

## Description
ForceV1 asks for information directly from the kernel space. Conhost connects to the console application. High IntegrityLevel means the process is running with elevated privileges, such as an Administrator context.

## References
https://cybercryptosec.medium.com/covid-19-cyber-infection-c615ead7c29
https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control

## False Positives
Very Likely, including launching cmd.exe via Run As Administrator

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "conhost.exe" AND TgtProcCmdLine containsCIS "0xffffffff" AND TgtProcCmdLine containsCIS "-ForceV1") AND (TgtProcIntegrityLevel In ("High","S-1-16-12288"))))

```