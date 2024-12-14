# proc_creation_win_mmc_mmc20_lateral_movement

## Title
MMC20 Lateral Movement

## ID
f1f3bf22-deb2-418d-8cce-e1a45e46a5bd

## Author
@2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea)

## Date
2020-03-04

## Tags
attack.execution, attack.t1021.003

## Description
Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe

## References
https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "-Embedding" AND TgtProcImagePath endswithCIS "\mmc.exe" AND SrcProcImagePath endswithCIS "\svchost.exe"))

```