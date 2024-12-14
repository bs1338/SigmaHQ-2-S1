# proc_creation_win_wmi_backdoor_exchange_transport_agent

## Title
WMI Backdoor Exchange Transport Agent

## ID
797011dc-44f4-4e6f-9f10-a8ceefbe566b

## Author
Florian Roth (Nextron Systems)

## Date
2019-10-11

## Tags
attack.persistence, attack.t1546.003

## Description
Detects a WMI backdoor in Exchange Transport Agents via WMI event filters

## References
https://twitter.com/cglyer/status/1182389676876980224
https://twitter.com/cglyer/status/1182391019633029120

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\EdgeTransport.exe" AND (NOT (TgtProcImagePath = "C:\Windows\System32\conhost.exe" OR (TgtProcImagePath endswithCIS "\Bin\OleConverter.exe" AND TgtProcImagePath startswithCIS "C:\Program Files\Microsoft\Exchange Server\")))))

```