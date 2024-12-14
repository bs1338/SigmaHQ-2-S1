# proc_creation_win_pua_3proxy_execution

## Title
PUA - 3Proxy Execution

## ID
f38a82d2-fba3-4781-b549-525efbec8506

## Author
Florian Roth (Nextron Systems)

## Date
2022-09-13

## Tags
attack.command-and-control, attack.t1572

## Description
Detects the use of 3proxy, a tiny free proxy server

## References
https://github.com/3proxy/3proxy
https://blog.talosintelligence.com/2022/09/lazarus-three-rats.html

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\3proxy.exe" OR TgtProcCmdLine containsCIS ".exe -i127.0.0.1 -p" OR TgtProcDisplayName = "3proxy - tiny proxy server"))

```