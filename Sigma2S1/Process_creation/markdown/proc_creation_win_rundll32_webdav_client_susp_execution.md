# proc_creation_win_rundll32_webdav_client_susp_execution

## Title
Suspicious WebDav Client Execution Via Rundll32.EXE

## ID
982e9f2d-1a85-4d5b-aea4-31f5e97c6555

## Author
Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)

## Date
2023-03-16

## Tags
attack.exfiltration, attack.t1048.003, cve.2023-23397

## Description
Detects "svchost.exe" spawning "rundll32.exe" with command arguments like C:\windows\system32\davclnt.dll,DavSetCookie. This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server) or potentially a sign of exploitation of CVE-2023-23397


## References
https://twitter.com/aceresponder/status/1636116096506818562
https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/
https://www.pwndefend.com/2023/03/15/the-long-game-persistent-hash-theft/
https://www.microsoft.com/en-us/security/blog/wp-content/uploads/2023/03/Figure-7-sample-webdav-process-create-event.png
https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "C:\windows\system32\davclnt.dll,DavSetCookie" AND TgtProcCmdLine RegExp "://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" AND TgtProcImagePath endswithCIS "\rundll32.exe" AND SrcProcCmdLine containsCIS "-s WebClient" AND SrcProcImagePath endswithCIS "\svchost.exe") AND (NOT (TgtProcCmdLine containsCIS "://10." OR TgtProcCmdLine containsCIS "://192.168." OR TgtProcCmdLine containsCIS "://172.16." OR TgtProcCmdLine containsCIS "://172.17." OR TgtProcCmdLine containsCIS "://172.18." OR TgtProcCmdLine containsCIS "://172.19." OR TgtProcCmdLine containsCIS "://172.20." OR TgtProcCmdLine containsCIS "://172.21." OR TgtProcCmdLine containsCIS "://172.22." OR TgtProcCmdLine containsCIS "://172.23." OR TgtProcCmdLine containsCIS "://172.24." OR TgtProcCmdLine containsCIS "://172.25." OR TgtProcCmdLine containsCIS "://172.26." OR TgtProcCmdLine containsCIS "://172.27." OR TgtProcCmdLine containsCIS "://172.28." OR TgtProcCmdLine containsCIS "://172.29." OR TgtProcCmdLine containsCIS "://172.30." OR TgtProcCmdLine containsCIS "://172.31." OR TgtProcCmdLine containsCIS "://127." OR TgtProcCmdLine containsCIS "://169.254."))))

```