# proc_creation_win_browsers_remote_debugging

## Title
Browser Started with Remote Debugging

## ID
b3d34dc5-2efd-4ae3-845f-8ec14921f449

## Author
pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-27

## Tags
attack.credential-access, attack.t1185

## Description
Detects browsers starting with the remote debugging flags. Which is a technique often used to perform browser injection attacks

## References
https://yoroi.company/wp-content/uploads/2022/05/EternityGroup_report_compressed.pdf
https://www.mdsec.co.uk/2022/10/analysing-lastpass-part-1/
https://github.com/defaultnamehere/cookie_crimes/
https://github.com/wunderwuzzi23/firefox-cookiemonster

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " --remote-debugging-" OR (TgtProcCmdLine containsCIS " -start-debugger-server" AND TgtProcImagePath endswithCIS "\firefox.exe")))

```