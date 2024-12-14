# proc_creation_win_svchost_execution_with_no_cli_flags

## Title
Suspect Svchost Activity

## ID
16c37b52-b141-42a5-a3ea-bbe098444397

## Author
David Burkett, @signalblur

## Date
2019-12-28

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1055

## Description
It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.

## References
https://web.archive.org/web/20180718061628/https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2

## False Positives
Rpcnet.exe / rpcnetp.exe which is a lojack style software. https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS "svchost.exe" AND TgtProcImagePath endswithCIS "\svchost.exe") AND (NOT ((SrcProcImagePath endswithCIS "\rpcnet.exe" OR SrcProcImagePath endswithCIS "\rpcnetp.exe") OR TgtProcCmdLine IS NOT EMPTY))))

```