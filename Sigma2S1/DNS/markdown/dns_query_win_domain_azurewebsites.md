# dns_query_win_domain_azurewebsites

## Title
DNS Query To AzureWebsites.NET By Non-Browser Process

## ID
e043f529-8514-4205-8ab0-7f7d2927b400

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-06-24

## Tags
attack.command-and-control, attack.t1219

## Description
Detects a DNS query by a non browser process on the system to "azurewebsites.net". The latter was often used by threat actors as a malware hosting and exfiltration site.


## References
https://www.sentinelone.com/labs/wip26-espionage-threat-actors-abuse-cloud-infrastructure-in-targeted-telco-attacks/
https://symantec-enterprise-blogs.security.com/threat-intelligence/harvester-new-apt-attacks-asia
https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
https://intezer.com/blog/research/how-we-escaped-docker-in-azure-functions/

## False Positives
Likely with other browser software. Apply additional filters for any other browsers you might use.

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND (DnsRequest endswithCIS "azurewebsites.net" AND (NOT ((SrcProcImagePath endswithCIS "\avant.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files (x86)\Avant Browser\" OR SrcProcImagePath startswithCIS "C:\Program Files\Avant Browser\")) OR (SrcProcImagePath endswithCIS "\brave.exe" AND SrcProcImagePath startswithCIS "C:\Program Files\BraveSoftware\") OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files\Google\Chrome\Application\chrome.exe","C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")) OR (SrcProcImagePath endswithCIS "\MsMpEng.exe" OR SrcProcImagePath endswithCIS "\MsSense.exe") OR (SrcProcImagePath startswithCIS "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\" OR SrcProcImagePath endswithCIS "\WindowsApps\MicrosoftEdge.exe" OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe","C:\Program Files\Microsoft\Edge\Application\msedge.exe"))) OR ((SrcProcImagePath endswithCIS "\msedge.exe" OR SrcProcImagePath endswithCIS "\msedgewebview2.exe") AND (SrcProcImagePath startswithCIS "C:\Program Files (x86)\Microsoft\EdgeCore\" OR SrcProcImagePath startswithCIS "C:\Program Files\Microsoft\EdgeCore\")) OR (SrcProcImagePath endswithCIS "\falkon.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Falkon\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Falkon\")) OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files\Mozilla Firefox\firefox.exe","C:\Program Files (x86)\Mozilla Firefox\firefox.exe")) OR (SrcProcImagePath containsCIS "\AppData\Local\Flock\" AND SrcProcImagePath endswithCIS "\Flock.exe") OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Internet Explorer\iexplore.exe","C:\Program Files\Internet Explorer\iexplore.exe")) OR (SrcProcImagePath containsCIS "\AppData\Local\Maxthon\" AND SrcProcImagePath endswithCIS "\maxthon.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\Programs\midori-ng\" AND SrcProcImagePath endswithCIS "\Midori Next Generation.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\Programs\Opera\" AND SrcProcImagePath endswithCIS "\opera.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\Phoebe\" AND SrcProcImagePath endswithCIS "\Phoebe.exe") OR SrcProcImagePath endswithCIS "\safari.exe" OR (SrcProcImagePath endswithCIS "\seamonkey.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\SeaMonkey\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\SeaMonkey\")) OR (SrcProcImagePath endswithCIS "\slimbrowser.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\SlimBrowser\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\SlimBrowser\")) OR SrcProcImagePath containsCIS "\Tor Browser\" OR (SrcProcImagePath containsCIS "\AppData\Local\Vivaldi\" AND SrcProcImagePath endswithCIS "\vivaldi.exe") OR (SrcProcImagePath endswithCIS "\whale.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Naver\Naver Whale\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Naver\Naver Whale\")) OR (SrcProcImagePath endswithCIS "\Waterfox.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Waterfox\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Waterfox\"))))))

```