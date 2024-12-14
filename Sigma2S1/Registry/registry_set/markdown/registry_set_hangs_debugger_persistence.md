# registry_set_hangs_debugger_persistence

## Title
Add Debugger Entry To Hangs Key For Persistence

## ID
833ef470-fa01-4631-a79b-6f291c9ac498

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-21

## Tags
attack.persistence

## Description
Detects when an attacker adds a new "Debugger" value to the "Hangs" key in order to achieve persistence which will get invoked when an application crashes

## References
https://persistence-info.github.io/Data/wer_debugger.html
https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/

## False Positives
This value is not set by default but could be rarly used by administrators

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs\Debugger")

```