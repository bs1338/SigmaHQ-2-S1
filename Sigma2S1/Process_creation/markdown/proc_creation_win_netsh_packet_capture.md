# proc_creation_win_netsh_packet_capture

## Title
New Network Trace Capture Started Via Netsh.EXE

## ID
d3c3861d-c504-4c77-ba55-224ba82d0118

## Author
Kutepov Anton, oscd.community

## Date
2019-10-24

## Tags
attack.discovery, attack.credential-access, attack.t1040

## Description
Detects the execution of netsh with the "trace" flag in order to start a network capture

## References
https://blogs.msdn.microsoft.com/canberrapfe/2012/03/30/capture-a-network-trace-without-installing-anything-capture-a-network-trace-of-a-reboot/
https://klausjochem.me/2016/02/03/netsh-the-cyber-attackers-tool-of-choice/

## False Positives
Legitimate administration activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "trace" AND TgtProcCmdLine containsCIS "start") AND TgtProcImagePath endswithCIS "\netsh.exe"))

```