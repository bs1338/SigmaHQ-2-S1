# proc_creation_win_sysinternals_procdump_lsass

## Title
Potential LSASS Process Dump Via Procdump

## ID
5afee48e-67dd-4e03-a783-f74259dcf998

## Author
Florian Roth (Nextron Systems)

## Date
2018-10-30

## Tags
attack.defense-evasion, attack.t1036, attack.credential-access, attack.t1003.001, car.2013-05-009

## Description
Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process.
This way we are also able to catch cases in which the attacker has renamed the procdump executable.


## References
https://learn.microsoft.com/en-us/sysinternals/downloads/procdump

## False Positives
Unlikely, because no one should dump an lsass process memory
Another tool that uses command line flags similar to ProcDump

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -ma " OR TgtProcCmdLine containsCIS " /ma " OR TgtProcCmdLine containsCIS " â€“ma " OR TgtProcCmdLine containsCIS " â€”ma " OR TgtProcCmdLine containsCIS " â€•ma ") AND TgtProcCmdLine containsCIS " ls"))

```