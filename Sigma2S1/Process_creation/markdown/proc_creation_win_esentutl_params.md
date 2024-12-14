# proc_creation_win_esentutl_params

## Title
Esentutl Gather Credentials

## ID
7df1713a-1a5b-4a4b-a071-dc83b144a101

## Author
sam0x90

## Date
2021-08-06

## Tags
attack.credential-access, attack.t1003, attack.t1003.003

## Description
Conti recommendation to its affiliates to use esentutl to access NTDS dumped file. Trickbot also uses this utilities to get MSEdge info via its module pwgrab.

## References
https://twitter.com/vxunderground/status/1423336151860002816
https://attack.mitre.org/software/S0404/
https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/

## False Positives
To be determined

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "esentutl" AND TgtProcCmdLine containsCIS " /p"))

```