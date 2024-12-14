# file_event_win_susp_recycle_bin_fake_exec

## Title
Suspicious File Creation Activity From Fake Recycle.Bin Folder

## ID
cd8b36ac-8e4a-4c2f-a402-a29b8fbd5bca

## Author
X__Junior (Nextron Systems)

## Date
2023-07-12

## Tags
attack.persistence, attack.defense-evasion

## Description
Detects file write event from/to a fake recycle bin folder that is often used as a staging directory for malware

## References
https://www.mandiant.com/resources/blog/infected-usb-steal-secrets
https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath containsCIS "RECYCLERS.BIN\" OR SrcProcImagePath containsCIS "RECYCLER.BIN\") OR (TgtFilePath containsCIS "RECYCLERS.BIN\" OR TgtFilePath containsCIS "RECYCLER.BIN\")))

```