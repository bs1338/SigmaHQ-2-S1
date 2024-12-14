# proc_creation_win_cmd_curl_download_exec_combo

## Title
Curl Download And Execute Combination

## ID
21dd6d38-2b18-4453-9404-a0fe4a0cc288

## Author
Sreeman, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-01-13

## Tags
attack.defense-evasion, attack.t1218, attack.command-and-control, attack.t1105

## Description
Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.

## References
https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "curl " AND TgtProcCmdLine containsCIS "http" AND TgtProcCmdLine containsCIS "-o" AND TgtProcCmdLine containsCIS "&") AND (TgtProcCmdLine containsCIS " -c " OR TgtProcCmdLine containsCIS " /c " OR TgtProcCmdLine containsCIS " â€“c " OR TgtProcCmdLine containsCIS " â€”c " OR TgtProcCmdLine containsCIS " â€•c ")))

```