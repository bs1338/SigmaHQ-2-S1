# proc_creation_win_lolbin_susp_driver_installed_by_pnputil

## Title
Suspicious Driver Install by pnputil.exe

## ID
a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1

## Author
Hai Vaknin @LuxNoBulIshit, Avihay eldad  @aloneliassaf, Austin Songer @austinsonger

## Date
2021-09-30

## Tags
attack.persistence, attack.t1547

## Description
Detects when a possible suspicious driver is being installed via pnputil.exe lolbin

## References
https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax
https://strontic.github.io/xcyclopedia/library/pnputil.exe-60EDC5E6BDBAEE441F2E3AEACD0340D2.html

## False Positives
Pnputil.exe being used may be performed by a system administrator.
Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
Pnputil.exe being executed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-i" OR TgtProcCmdLine containsCIS "/install" OR TgtProcCmdLine containsCIS "-a" OR TgtProcCmdLine containsCIS "/add-driver" OR TgtProcCmdLine containsCIS ".inf") AND TgtProcImagePath endswithCIS "\pnputil.exe"))

```