# proc_creation_win_lolbin_tttracer_mod_load

## Title
Time Travel Debugging Utility Usage

## ID
0b4ae027-2a2d-4b93-8c7e-962caaba5b2a

## Author
Ensar Şamil, @sblmsrsn, @oscd_initiative

## Date
2020-10-06

## Tags
attack.defense-evasion, attack.credential-access, attack.t1218, attack.t1003.001

## Description
Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.

## References
https://lolbas-project.github.io/lolbas/Binaries/Tttracer/
https://twitter.com/mattifestation/status/1196390321783025666
https://twitter.com/oulusoyum/status/1191329746069655553

## False Positives
Legitimate usage by software developers/testers

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\tttracer.exe")

```