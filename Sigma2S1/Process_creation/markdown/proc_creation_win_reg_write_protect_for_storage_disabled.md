# proc_creation_win_reg_write_protect_for_storage_disabled

## Title
Write Protect For Storage Disabled

## ID
75f7a0e2-7154-4c4d-9eae-5cdb4e0a5c13

## Author
Sreeman

## Date
2021-06-11

## Tags
attack.defense-evasion, attack.t1562

## Description
Detects applications trying to modify the registry in order to disable any write-protect property for storage devices.
This could be a precursor to a ransomware attack and has been an observed technique used by cypherpunk group.


## References
https://www.manageengine.com/products/desktop-central/os-imaging-deployment/media-is-write-protected.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\System\CurrentControlSet\Control" AND TgtProcCmdLine containsCIS "Write Protection" AND TgtProcCmdLine containsCIS "0" AND TgtProcCmdLine containsCIS "storage"))

```