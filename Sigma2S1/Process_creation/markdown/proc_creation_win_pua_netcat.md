# proc_creation_win_pua_netcat

## Title
PUA - Netcat Suspicious Execution

## ID
e31033fc-33f0-4020-9a16-faf9b31cbf08

## Author
frack113, Florian Roth (Nextron Systems)

## Date
2021-07-21

## Tags
attack.command-and-control, attack.t1095

## Description
Detects execution of Netcat. Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network

## References
https://nmap.org/ncat/
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1095/T1095.md
https://www.revshells.com/

## False Positives
Legitimate ncat use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -lvp " OR TgtProcCmdLine containsCIS " -lvnp" OR TgtProcCmdLine containsCIS " -l -v -p " OR TgtProcCmdLine containsCIS " -lv -p " OR TgtProcCmdLine containsCIS " -l --proxy-type http " OR TgtProcCmdLine containsCIS " -vnl --exec " OR TgtProcCmdLine containsCIS " -vnl -e " OR TgtProcCmdLine containsCIS " --lua-exec " OR TgtProcCmdLine containsCIS " --sh-exec ") OR (TgtProcImagePath endswithCIS "\nc.exe" OR TgtProcImagePath endswithCIS "\ncat.exe" OR TgtProcImagePath endswithCIS "\netcat.exe")))

```