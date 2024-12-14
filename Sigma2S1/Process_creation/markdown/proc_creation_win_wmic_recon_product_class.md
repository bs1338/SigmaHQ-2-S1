# proc_creation_win_wmic_recon_product_class

## Title
Potential Product Class Reconnaissance Via Wmic.EXE

## ID
e568650b-5dcd-4658-8f34-ded0b1e13992

## Author
Michael Haag, Florian Roth (Nextron Systems), juju4, oscd.community

## Date
2023-02-14

## Tags
attack.execution, attack.t1047, car.2016-03-002

## Description
Detects the execution of WMIC in order to get a list of firewall and antivirus products

## References
https://github.com/albertzsigovits/malware-notes/blob/c820c7fea76cf76a861b28ebc77e06100e20ec29/Ransomware/Maze.md
https://www.hybrid-analysis.com/sample/4be06ecd234e2110bd615649fe4a6fa95403979acf889d7e45a78985eb50acf9?environmentId=1

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "AntiVirusProduct" OR TgtProcCmdLine containsCIS "FirewallProduct") AND TgtProcImagePath endswithCIS "\wmic.exe"))

```