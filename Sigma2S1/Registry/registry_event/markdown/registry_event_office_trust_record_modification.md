# registry_event_office_trust_record_modification

## Title
Windows Registry Trust Record Modification

## ID
295a59c1-7b79-4b47-a930-df12c15fc9c2

## Author
Antonlovesdnb, Trent Liffick (@tliffick)

## Date
2020-02-19

## Tags
attack.initial-access, attack.t1566.001

## Description
Alerts on trust record modification within the registry, indicating usage of macros

## References
https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html
https://twitter.com/inversecos/status/1494174785621819397

## False Positives
This will alert on legitimate macro usage as well, additional tuning is required

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\Security\Trusted Documents\TrustRecords")

```