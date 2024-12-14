# proc_creation_win_susp_recycle_bin_fake_execution

## Title
Suspicious Process Execution From Fake Recycle.Bin Folder

## ID
5ce0f04e-3efc-42af-839d-5b3a543b76c0

## Author
X__Junior (Nextron Systems)

## Date
2023-07-12

## Tags
attack.persistence, attack.defense-evasion

## Description
Detects process execution from a fake recycle bin folder, often used to avoid security solution.

## References
https://www.mandiant.com/resources/blog/infected-usb-steal-secrets
https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath containsCIS "RECYCLERS.BIN\" OR TgtProcImagePath containsCIS "RECYCLER.BIN\"))

```