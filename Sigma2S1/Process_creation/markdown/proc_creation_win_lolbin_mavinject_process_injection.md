# proc_creation_win_lolbin_mavinject_process_injection

## Title
Mavinject Inject DLL Into Running Process

## ID
4f73421b-5a0b-4bbf-a892-5a7fb99bea66

## Author
frack113, Florian Roth

## Date
2021-07-12

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1055.001, attack.t1218.013

## Description
Detects process injection using the signed Windows tool "Mavinject" via the "INJECTRUNNING" flag

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1056.004/T1056.004.md
https://posts.specterops.io/mavinject-exe-functionality-deconstructed-c29ab2cf5c0e
https://twitter.com/gN3mes1s/status/941315826107510784
https://reaqta.com/2017/12/mavinject-microsoft-injector/
https://twitter.com/Hexacorn/status/776122138063409152
https://github.com/SigmaHQ/sigma/issues/3742
https://github.com/keyboardcrunch/SentinelOne-ATTACK-Queries/blob/6a228d23eefe963ca81f2d52f94b815f61ef5ee0/Tactics/DefenseEvasion.md#t1055-process-injection

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " /INJECTRUNNING " AND (NOT SrcProcImagePath = "C:\Windows\System32\AppVClient.exe")))

```