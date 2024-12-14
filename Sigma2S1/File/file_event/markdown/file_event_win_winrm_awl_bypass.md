# file_event_win_winrm_awl_bypass

## Title
AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File

## ID
d353dac0-1b41-46c2-820c-d7d2561fc6ed

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
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "WsmPty.xsl" OR TgtFilePath endswithCIS "WsmTxt.xsl") AND (NOT (TgtFilePath startswithCIS "C:\Windows\System32\" OR TgtFilePath startswithCIS "C:\Windows\SysWOW64\"))))

```