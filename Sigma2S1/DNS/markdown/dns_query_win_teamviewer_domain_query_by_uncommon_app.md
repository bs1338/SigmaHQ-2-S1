# dns_query_win_teamviewer_domain_query_by_uncommon_app

## Title
TeamViewer Domain Query By Non-TeamViewer Application

## ID
778ba9a8-45e4-4b80-8e3e-34a419f0b85e

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-30

## Tags
attack.command-and-control, attack.t1219

## Description
Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)

## References
https://www.teamviewer.com/en-us/

## False Positives
Unknown binary names of TeamViewer
Depending on the environment the rule might require some initial tuning before usage to avoid FP with third party applications

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND ((DnsRequest In Contains AnyCase ("taf.teamviewer.com","udp.ping.teamviewer.com")) AND (NOT SrcProcImagePath containsCIS "TeamViewer")))

```