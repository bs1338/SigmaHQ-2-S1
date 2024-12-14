# proc_creation_win_wmic_xsl_script_processing

## Title
XSL Script Execution Via WMIC.EXE

## ID
05c36dd6-79d6-4a9a-97da-3db20298ab2d

## Author
Timur Zinniatullin, oscd.community, Swachchhanda Shrawan Poudel

## Date
2019-10-21

## Tags
attack.defense-evasion, attack.t1220

## Description
Detects the execution of WMIC with the "format" flag to potentially load XSL files.
Adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.
Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1220/T1220.md

## False Positives
WMIC.exe FP depend on scripts and administrative methods used in the monitored environment.
Static format arguments - https://petri.com/command-line-wmi-part-3

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-format" OR TgtProcCmdLine containsCIS "/format" OR TgtProcCmdLine containsCIS "â€“format" OR TgtProcCmdLine containsCIS "â€”format" OR TgtProcCmdLine containsCIS "â€•format") AND TgtProcImagePath endswithCIS "\wmic.exe") AND (NOT (TgtProcCmdLine containsCIS "Format:List" OR TgtProcCmdLine containsCIS "Format:htable" OR TgtProcCmdLine containsCIS "Format:hform" OR TgtProcCmdLine containsCIS "Format:table" OR TgtProcCmdLine containsCIS "Format:mof" OR TgtProcCmdLine containsCIS "Format:value" OR TgtProcCmdLine containsCIS "Format:rawxml" OR TgtProcCmdLine containsCIS "Format:xml" OR TgtProcCmdLine containsCIS "Format:csv"))))

```