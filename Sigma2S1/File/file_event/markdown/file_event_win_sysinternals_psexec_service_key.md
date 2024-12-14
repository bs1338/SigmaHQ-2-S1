# file_event_win_sysinternals_psexec_service_key

## Title
PSEXEC Remote Execution File Artefact

## ID
304afd73-55a5-4bb9-8c21-0b1fc84ea9e4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-21

## Tags
attack.lateral-movement, attack.privilege-escalation, attack.execution, attack.persistence, attack.t1136.002, attack.t1543.003, attack.t1570, attack.s0029

## Description
Detects creation of the PSEXEC key file. Which is created anytime a PsExec command is executed. It gets written to the file system and will be recorded in the USN Journal on the target system

## References
https://aboutdfir.com/the-key-to-identify-psexec/
https://twitter.com/davisrichardg/status/1616518800584704028

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".key" AND TgtFilePath startswithCIS "C:\Windows\PSEXEC-"))

```