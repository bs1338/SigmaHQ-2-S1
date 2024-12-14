# proc_creation_win_hktl_execution_via_pe_metadata

## Title
Hacktool Execution - PE Metadata

## ID
37c1333a-a0db-48be-b64b-7393b2386e3b

## Author
Florian Roth (Nextron Systems)

## Date
2022-04-27

## Tags
attack.credential-access, attack.t1588.002, attack.t1003

## Description
Detects the execution of different Windows based hacktools via PE metadata (company, product, etc.) even if the files have been renamed

## References
https://github.com/cube0x0
https://www.virustotal.com/gui/search/metadata%253ACube0x0/files

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcPublisher = "Cube0x0")

```