# proc_creation_win_netsh_fw_enable_group_rule

## Title
Netsh Allow Group Policy on Microsoft Defender Firewall

## ID
347906f3-e207-4d18-ae5b-a9403d6bcdef

## Author
frack113

## Date
2022-01-09

## Tags
attack.defense-evasion, attack.t1562.004

## Description
Adversaries may modify system firewalls in order to bypass controls limiting network usage

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md#atomic-test-3---allow-smb-and-rdp-on-microsoft-defender-firewall
https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior

## False Positives
Legitimate administration activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "advfirewall" AND TgtProcCmdLine containsCIS "firewall" AND TgtProcCmdLine containsCIS "set" AND TgtProcCmdLine containsCIS "rule" AND TgtProcCmdLine containsCIS "group=" AND TgtProcCmdLine containsCIS "new" AND TgtProcCmdLine containsCIS "enable=Yes") AND TgtProcImagePath endswithCIS "\netsh.exe"))

```