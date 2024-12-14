# dns_query_win_susp_external_ip_lookup

## Title
Suspicious DNS Query for IP Lookup Service APIs

## ID
ec82e2a5-81ea-4211-a1f8-37a0286df2c2

## Author
Brandon George (blog post), Thomas Patzke

## Date
2021-07-08

## Tags
attack.reconnaissance, attack.t1590

## Description
Detects DNS queries for IP lookup services such as "api.ipify.org" originating from a non browser process.

## References
https://www.binarydefense.com/analysis-of-hancitor-when-boring-begets-beacon
https://twitter.com/neonprimetime/status/1436376497980428318
https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html

## False Positives
Legitimate usage of IP lookup services such as ipify API

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND (((DnsRequest In Contains AnyCase ("www.ip.cn","l2.io")) OR (DnsRequest containsCIS "api.2ip.ua" OR DnsRequest containsCIS "api.bigdatacloud.net" OR DnsRequest containsCIS "api.ipify.org" OR DnsRequest containsCIS "bot.whatismyipaddress.com" OR DnsRequest containsCIS "canireachthe.net" OR DnsRequest containsCIS "checkip.amazonaws.com" OR DnsRequest containsCIS "checkip.dyndns.org" OR DnsRequest containsCIS "curlmyip.com" OR DnsRequest containsCIS "db-ip.com" OR DnsRequest containsCIS "edns.ip-api.com" OR DnsRequest containsCIS "eth0.me" OR DnsRequest containsCIS "freegeoip.app" OR DnsRequest containsCIS "geoipy.com" OR DnsRequest containsCIS "getip.pro" OR DnsRequest containsCIS "icanhazip.com" OR DnsRequest containsCIS "ident.me" OR DnsRequest containsCIS "ifconfig.io" OR DnsRequest containsCIS "ifconfig.me" OR DnsRequest containsCIS "ip-api.com" OR DnsRequest containsCIS "ip.360.cn" OR DnsRequest containsCIS "ip.anysrc.net" OR DnsRequest containsCIS "ip.taobao.com" OR DnsRequest containsCIS "ip.tyk.nu" OR DnsRequest containsCIS "ipaddressworld.com" OR DnsRequest containsCIS "ipapi.co" OR DnsRequest containsCIS "ipconfig.io" OR DnsRequest containsCIS "ipecho.net" OR DnsRequest containsCIS "ipinfo.io" OR DnsRequest containsCIS "ipip.net" OR DnsRequest containsCIS "ipof.in" OR DnsRequest containsCIS "ipv4.icanhazip.com" OR DnsRequest containsCIS "ipv4bot.whatismyipaddress.com" OR DnsRequest containsCIS "ipv6-test.com" OR DnsRequest containsCIS "ipwho.is" OR DnsRequest containsCIS "jsonip.com" OR DnsRequest containsCIS "myexternalip.com" OR DnsRequest containsCIS "seeip.org" OR DnsRequest containsCIS "wgetip.com" OR DnsRequest containsCIS "whatismyip.akamai.com" OR DnsRequest containsCIS "whois.pconline.com.cn" OR DnsRequest containsCIS "wtfismyip.com")) AND (NOT (SrcProcImagePath endswithCIS "\brave.exe" OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files\Google\Chrome\Application\chrome.exe","C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")) OR (SrcProcImagePath startswithCIS "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\" OR SrcProcImagePath endswithCIS "\WindowsApps\MicrosoftEdge.exe" OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe","C:\Program Files\Microsoft\Edge\Application\msedge.exe"))) OR ((SrcProcImagePath endswithCIS "\msedge.exe" OR SrcProcImagePath endswithCIS "\msedgewebview2.exe") AND (SrcProcImagePath startswithCIS "C:\Program Files (x86)\Microsoft\EdgeCore\" OR SrcProcImagePath startswithCIS "C:\Program Files\Microsoft\EdgeCore\")) OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files\Mozilla Firefox\firefox.exe","C:\Program Files (x86)\Mozilla Firefox\firefox.exe")) OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Internet Explorer\iexplore.exe","C:\Program Files\Internet Explorer\iexplore.exe")) OR SrcProcImagePath endswithCIS "\maxthon.exe" OR SrcProcImagePath endswithCIS "\opera.exe" OR SrcProcImagePath endswithCIS "\safari.exe" OR SrcProcImagePath endswithCIS "\seamonkey.exe" OR SrcProcImagePath endswithCIS "\vivaldi.exe" OR SrcProcImagePath endswithCIS "\whale.exe"))))

```