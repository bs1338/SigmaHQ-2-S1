# registry_set_dns_over_https_enabled

## Title
DNS-over-HTTPS Enabled by Registry

## ID
04b45a8a-d11d-49e4-9acc-4a1b524407a5

## Author
Austin Songer

## Date
2021-07-22

## Tags
attack.defense-evasion, attack.t1140, attack.t1112

## Description
Detects when a user enables DNS-over-HTTPS.
This can be used to hide internet activity or be used to hide the process of exfiltrating data.
With this enabled organization will lose visibility into data such as query type, response and originating IP that are used to determine bad actors.


## References
https://www.tenforums.com/tutorials/151318-how-enable-disable-dns-over-https-doh-microsoft-edge.html
https://github.com/elastic/detection-rules/issues/1371
https://chromeenterprise.google/policies/?policy=DnsOverHttpsMode
https://admx.help/HKLM/Software/Policies/Mozilla/Firefox/DNSOverHTTPS

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "secure" AND RegistryKeyPath endswithCIS "\SOFTWARE\Google\Chrome\DnsOverHttpsMode") OR (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\SOFTWARE\Policies\Microsoft\Edge\BuiltInDnsClientEnabled") OR (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS\Enabled")))

```