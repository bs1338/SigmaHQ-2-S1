# proc_creation_win_hktl_impacket_tools

## Title
HackTool - Impacket Tools Execution

## ID
4627c6ae-6899-46e2-aa0c-6ebcb1becd19

## Author
Florian Roth (Nextron Systems)

## Date
2021-07-24

## Tags
attack.execution, attack.t1557.001

## Description
Detects the execution of different compiled Windows binaries of the impacket toolset (based on names or part of their names - could lead to false positives)

## References
https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries

## False Positives
Legitimate use of the impacket tools

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS "\goldenPac" OR TgtProcImagePath containsCIS "\karmaSMB" OR TgtProcImagePath containsCIS "\kintercept" OR TgtProcImagePath containsCIS "\ntlmrelayx" OR TgtProcImagePath containsCIS "\rpcdump" OR TgtProcImagePath containsCIS "\samrdump" OR TgtProcImagePath containsCIS "\secretsdump" OR TgtProcImagePath containsCIS "\smbexec" OR TgtProcImagePath containsCIS "\smbrelayx" OR TgtProcImagePath containsCIS "\wmiexec" OR TgtProcImagePath containsCIS "\wmipersist") OR (TgtProcImagePath endswithCIS "\atexec_windows.exe" OR TgtProcImagePath endswithCIS "\dcomexec_windows.exe" OR TgtProcImagePath endswithCIS "\dpapi_windows.exe" OR TgtProcImagePath endswithCIS "\findDelegation_windows.exe" OR TgtProcImagePath endswithCIS "\GetADUsers_windows.exe" OR TgtProcImagePath endswithCIS "\GetNPUsers_windows.exe" OR TgtProcImagePath endswithCIS "\getPac_windows.exe" OR TgtProcImagePath endswithCIS "\getST_windows.exe" OR TgtProcImagePath endswithCIS "\getTGT_windows.exe" OR TgtProcImagePath endswithCIS "\GetUserSPNs_windows.exe" OR TgtProcImagePath endswithCIS "\ifmap_windows.exe" OR TgtProcImagePath endswithCIS "\mimikatz_windows.exe" OR TgtProcImagePath endswithCIS "\netview_windows.exe" OR TgtProcImagePath endswithCIS "\nmapAnswerMachine_windows.exe" OR TgtProcImagePath endswithCIS "\opdump_windows.exe" OR TgtProcImagePath endswithCIS "\psexec_windows.exe" OR TgtProcImagePath endswithCIS "\rdp_check_windows.exe" OR TgtProcImagePath endswithCIS "\sambaPipe_windows.exe" OR TgtProcImagePath endswithCIS "\smbclient_windows.exe" OR TgtProcImagePath endswithCIS "\smbserver_windows.exe" OR TgtProcImagePath endswithCIS "\sniff_windows.exe" OR TgtProcImagePath endswithCIS "\sniffer_windows.exe" OR TgtProcImagePath endswithCIS "\split_windows.exe" OR TgtProcImagePath endswithCIS "\ticketer_windows.exe")))

```