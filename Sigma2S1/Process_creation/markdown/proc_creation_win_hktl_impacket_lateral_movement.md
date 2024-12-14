# proc_creation_win_hktl_impacket_lateral_movement

## Title
HackTool - Potential Impacket Lateral Movement Activity

## ID
10c14723-61c7-4c75-92ca-9af245723ad2

## Author
Ecco, oscd.community, Jonhnathan Ribeiro, Tim Rauch

## Date
2019-09-03

## Tags
attack.execution, attack.t1047, attack.lateral-movement, attack.t1021.003

## Description
Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework

## References
https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/wmiexec.py
https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/atexec.py
https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/smbexec.py
https://github.com/SecureAuthCorp/impacket/blob/8b1a99f7c715702eafe3f24851817bb64721b156/examples/dcomexec.py
https://www.elastic.co/guide/en/security/current/suspicious-cmd-execution-via-wmi.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "cmd.exe" AND TgtProcCmdLine containsCIS "/C" AND TgtProcCmdLine containsCIS "Windows\Temp\" AND TgtProcCmdLine containsCIS "&1") AND (SrcProcCmdLine containsCIS "svchost.exe -k netsvcs" OR SrcProcCmdLine containsCIS "taskeng.exe")) OR ((TgtProcCmdLine containsCIS "cmd.exe" AND TgtProcCmdLine containsCIS "/Q" AND TgtProcCmdLine containsCIS "/c" AND TgtProcCmdLine containsCIS "\\127.0.0.1\" AND TgtProcCmdLine containsCIS "&1") AND (SrcProcImagePath endswithCIS "\wmiprvse.exe" OR SrcProcImagePath endswithCIS "\mmc.exe" OR SrcProcImagePath endswithCIS "\explorer.exe" OR SrcProcImagePath endswithCIS "\services.exe"))))

```