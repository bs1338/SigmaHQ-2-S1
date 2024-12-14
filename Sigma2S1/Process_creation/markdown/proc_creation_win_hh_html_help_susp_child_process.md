# proc_creation_win_hh_html_help_susp_child_process

## Title
HTML Help HH.EXE Suspicious Child Process

## ID
52cad028-0ff0-4854-8f67-d25dfcbc78b4

## Author
Maxim Pavlunin, Nasreddine Bencherchali (Nextron Systems)

## Date
2020-04-01

## Tags
attack.defense-evasion, attack.execution, attack.initial-access, attack.t1047, attack.t1059.001, attack.t1059.003, attack.t1059.005, attack.t1059.007, attack.t1218, attack.t1218.001, attack.t1218.010, attack.t1218.011, attack.t1566, attack.t1566.001

## Description
Detects a suspicious child process of a Microsoft HTML Help (HH.exe)

## References
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/
https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-27939090904026cc396b0b629c8e4314acd6f5dac40a676edbc87f4567b47eb7
https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\CertReq.exe" OR TgtProcImagePath endswithCIS "\CertUtil.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\installutil.exe" OR TgtProcImagePath endswithCIS "\MSbuild.exe" OR TgtProcImagePath endswithCIS "\MSHTA.EXE" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\hh.exe"))

```