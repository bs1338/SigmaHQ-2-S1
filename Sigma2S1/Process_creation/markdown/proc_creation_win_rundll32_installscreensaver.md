# proc_creation_win_rundll32_installscreensaver

## Title
Rundll32 InstallScreenSaver Execution

## ID
15bd98ea-55f4-4d37-b09a-e7caa0fa2221

## Author
Christopher Peacock @securepeacock, SCYTHE @scythe_io, TactiKoolSec

## Date
2022-04-28

## Tags
attack.t1218.011, attack.defense-evasion

## Description
An attacker may execute an application as a SCR File using rundll32.exe desk.cpl,InstallScreenSaver

## References
https://lolbas-project.github.io/lolbas/Libraries/Desk/
https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1218.011/T1218.011.md#atomic-test-13---rundll32-with-deskcpl

## False Positives
Legitimate installation of a new screensaver

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "InstallScreenSaver" AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```