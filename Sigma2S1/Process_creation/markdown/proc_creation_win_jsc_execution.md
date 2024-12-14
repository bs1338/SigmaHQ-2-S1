# proc_creation_win_jsc_execution

## Title
JScript Compiler Execution

## ID
52788a70-f1da-40dd-8fbd-73b5865d6568

## Author
frack113

## Date
2022-05-02

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects the execution of the "jsc.exe" (JScript Compiler).
Attacker might abuse this in order to compile JScript files on the fly and bypassing application whitelisting.


## References
https://lolbas-project.github.io/lolbas/Binaries/Jsc/
https://www.phpied.com/make-your-javascript-a-windows-exe/
https://twitter.com/DissectMalware/status/998797808907046913

## False Positives
Legitimate use to compile JScript by developers.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\jsc.exe")

```