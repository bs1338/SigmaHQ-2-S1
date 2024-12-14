# proc_creation_win_lolbin_visual_basic_compiler

## Title
Visual Basic Command Line Compiler Usage

## ID
7b10f171-7f04-47c7-9fa2-5be43c76e535

## Author
Ensar Şamil, @sblmsrsn, @oscd_initiative

## Date
2020-10-07

## Tags
attack.defense-evasion, attack.t1027.004

## Description
Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.

## References
https://lolbas-project.github.io/lolbas/Binaries/Vbc/

## False Positives
Utilization of this tool should not be seen in enterprise environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\cvtres.exe" AND SrcProcImagePath endswithCIS "\vbc.exe"))

```