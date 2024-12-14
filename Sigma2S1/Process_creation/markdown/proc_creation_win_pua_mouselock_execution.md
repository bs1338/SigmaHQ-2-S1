# proc_creation_win_pua_mouselock_execution

## Title
PUA - Mouse Lock Execution

## ID
c9192ad9-75e5-43eb-8647-82a0a5b493e3

## Author
Cian Heasley

## Date
2020-08-13

## Tags
attack.credential-access, attack.collection, attack.t1056.002

## Description
In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool "Mouse Lock" as being used for both credential access and collection in security incidents.

## References
https://github.com/klsecservices/Publications/blob/657deb6a6eb6e00669afd40173f425fb49682eaa/Incident-Response-Analyst-Report-2020.pdf
https://sourceforge.net/projects/mouselock/

## False Positives
Legitimate uses of Mouse Lock software

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcDisplayName containsCIS "Mouse Lock" OR TgtProcPublisher containsCIS "Misc314" OR TgtProcCmdLine containsCIS "Mouse Lock_"))

```