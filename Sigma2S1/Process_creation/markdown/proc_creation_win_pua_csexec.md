# proc_creation_win_pua_csexec

## Title
PUA - CsExec Execution

## ID
d08a2711-ee8b-4323-bdec-b7d85e892b31

## Author
Florian Roth (Nextron Systems)

## Date
2022-08-22

## Tags
attack.resource-development, attack.t1587.001, attack.execution, attack.t1569.002

## Description
Detects the use of the lesser known remote execution tool named CsExec a PsExec alternative

## References
https://github.com/malcomvetter/CSExec
https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\csexec.exe" OR TgtProcDisplayName = "csexec"))

```