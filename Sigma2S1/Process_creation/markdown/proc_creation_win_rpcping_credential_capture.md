# proc_creation_win_rpcping_credential_capture

## Title
Capture Credentials with Rpcping.exe

## ID
93671f99-04eb-4ab4-a161-70d446a84003

## Author
Julia Fomina, oscd.community

## Date
2020-10-09

## Tags
attack.credential-access, attack.t1003

## Description
Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.

## References
https://lolbas-project.github.io/lolbas/Binaries/Rpcping/
https://twitter.com/vysecurity/status/974806438316072960
https://twitter.com/vysecurity/status/873181705024266241
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875578(v=ws.11)

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\rpcping.exe" AND (TgtProcCmdLine containsCIS "-s" OR TgtProcCmdLine containsCIS "/s" OR TgtProcCmdLine containsCIS "â€“s" OR TgtProcCmdLine containsCIS "â€”s" OR TgtProcCmdLine containsCIS "â€•s") AND (((TgtProcCmdLine containsCIS "-u" OR TgtProcCmdLine containsCIS "/u" OR TgtProcCmdLine containsCIS "â€“u" OR TgtProcCmdLine containsCIS "â€”u" OR TgtProcCmdLine containsCIS "â€•u") AND (TgtProcCmdLine containsCIS "NTLM")) OR ((TgtProcCmdLine containsCIS "-t" OR TgtProcCmdLine containsCIS "/t" OR TgtProcCmdLine containsCIS "â€“t" OR TgtProcCmdLine containsCIS "â€”t" OR TgtProcCmdLine containsCIS "â€•t") AND (TgtProcCmdLine containsCIS "ncacn_np")))))

```