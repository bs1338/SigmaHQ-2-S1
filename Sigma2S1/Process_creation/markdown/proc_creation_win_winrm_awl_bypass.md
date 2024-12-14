# proc_creation_win_winrm_awl_bypass

## Title
AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl

## ID
074e0ded-6ced-4ebd-8b4d-53f55908119d

## Author
Julia Fomina, oscd.community

## Date
2020-10-06

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)

## References
https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "winrm" AND ((TgtProcCmdLine containsCIS "format:pretty" OR TgtProcCmdLine containsCIS "format:\"pretty\"" OR TgtProcCmdLine containsCIS "format:\"text\"" OR TgtProcCmdLine containsCIS "format:text") AND (NOT (TgtProcImagePath startswithCIS "C:\Windows\System32\" OR TgtProcImagePath startswithCIS "C:\Windows\SysWOW64\")))))

```