# proc_creation_win_pdqdeploy_execution

## Title
PDQ Deploy Remote Adminstartion Tool Execution

## ID
d679950c-abb7-43a6-80fb-2a480c4fc450

## Author
frack113

## Date
2022-10-01

## Tags
attack.execution, attack.lateral-movement, attack.t1072

## Description
Detect use of PDQ Deploy remote admin tool

## References
https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1072/T1072.md
https://www.pdq.com/pdq-deploy/

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcDisplayName = "PDQ Deploy Console" OR TgtProcDisplayName = "PDQ Deploy" OR TgtProcPublisher = "PDQ.com"))

```