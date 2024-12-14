# dns_query_win_remote_access_software_domains_non_browsers

## Title
DNS Query To Remote Access Software Domain From Non-Browser App

## ID
4d07b1f4-cb00-4470-b9f8-b0191d48ff52

## Author
frack113, Connor Martin

## Date
2022-07-11

## Tags
attack.command-and-control, attack.t1219

## Description
An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-3---logmein-files-detected-test-on-windows
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-6---ammyy-admin-software-execution
https://redcanary.com/blog/misbehaving-rats/
https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/hunting-for-omi-vulnerability-exploitation-with-azure-sentinel/ba-p/2764093
https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
https://blog.sekoia.io/scattered-spider-laying-new-eggs/
https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist#disable-quick-assist-within-your-organization

## False Positives
Likely with other browser software. Apply additional filters for any other browsers you might use.

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND (((DnsRequest endswithCIS "agent.jumpcloud.com" OR DnsRequest endswithCIS "agentreporting.atera.com" OR DnsRequest endswithCIS "ammyy.com" OR DnsRequest endswithCIS "api.parsec.app" OR DnsRequest endswithCIS "api.playanext.com" OR DnsRequest endswithCIS "api.splashtop.com" OR DnsRequest endswithCIS "app.atera.com" OR DnsRequest endswithCIS "assist.zoho.com" OR DnsRequest endswithCIS "authentication.logmeininc.com" OR DnsRequest endswithCIS "beyondtrustcloud.com" OR DnsRequest endswithCIS "cdn.kaseya.net" OR DnsRequest endswithCIS "client.teamviewer.com" OR DnsRequest endswithCIS "comserver.corporate.beanywhere.com" OR DnsRequest endswithCIS "control.connectwise.com" OR DnsRequest endswithCIS "downloads.zohocdn.com" OR DnsRequest endswithCIS "dwservice.net" OR DnsRequest endswithCIS "express.gotoassist.com" OR DnsRequest endswithCIS "getgo.com" OR DnsRequest endswithCIS "integratedchat.teamviewer.com" OR DnsRequest endswithCIS "join.zoho.com" OR DnsRequest endswithCIS "kickstart.jumpcloud.com" OR DnsRequest endswithCIS "license.bomgar.com" OR DnsRequest endswithCIS "logmein-gateway.com" OR DnsRequest endswithCIS "logmein.com" OR DnsRequest endswithCIS "logmeincdn.http.internapcdn.net" OR DnsRequest endswithCIS "n-able.com" OR DnsRequest endswithCIS "net.anydesk.com" OR DnsRequest endswithCIS "netsupportsoftware.com" OR DnsRequest endswithCIS "parsecusercontent.com" OR DnsRequest endswithCIS "pubsub.atera.com" OR DnsRequest endswithCIS "relay.kaseya.net" OR DnsRequest endswithCIS "relay.screenconnect.com" OR DnsRequest endswithCIS "relay.splashtop.com" OR DnsRequest endswithCIS "remoteassistance.support.services.microsoft.com" OR DnsRequest endswithCIS "remotedesktop-pa.googleapis.com" OR DnsRequest endswithCIS "remoteutilities.com" OR DnsRequest endswithCIS "secure.logmeinrescue.com" OR DnsRequest endswithCIS "services.vnc.com" OR DnsRequest endswithCIS "static.remotepc.com" OR DnsRequest endswithCIS "swi-rc.com" OR DnsRequest endswithCIS "swi-tc.com" OR DnsRequest endswithCIS "tailscale.com" OR DnsRequest endswithCIS "telemetry.servers.qetqo.com" OR DnsRequest endswithCIS "tmate.io" OR DnsRequest endswithCIS "twingate.com" OR DnsRequest endswithCIS "zohoassist.com") OR (DnsRequest endswithCIS ".rustdesk.com" AND DnsRequest startswithCIS "rs-")) AND (NOT ((SrcProcImagePath endswithCIS "\avant.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files (x86)\Avant Browser\" OR SrcProcImagePath startswithCIS "C:\Program Files\Avant Browser\")) OR (SrcProcImagePath endswithCIS "\brave.exe" AND SrcProcImagePath startswithCIS "C:\Program Files\BraveSoftware\") OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files\Google\Chrome\Application\chrome.exe","C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")) OR (SrcProcImagePath endswithCIS "\MsMpEng.exe" OR SrcProcImagePath endswithCIS "\MsSense.exe") OR (SrcProcImagePath startswithCIS "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\" OR SrcProcImagePath endswithCIS "\WindowsApps\MicrosoftEdge.exe" OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe","C:\Program Files\Microsoft\Edge\Application\msedge.exe"))) OR ((SrcProcImagePath endswithCIS "\msedge.exe" OR SrcProcImagePath endswithCIS "\msedgewebview2.exe") AND (SrcProcImagePath startswithCIS "C:\Program Files (x86)\Microsoft\EdgeCore\" OR SrcProcImagePath startswithCIS "C:\Program Files\Microsoft\EdgeCore\")) OR (SrcProcImagePath endswithCIS "\falkon.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Falkon\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Falkon\")) OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files\Mozilla Firefox\firefox.exe","C:\Program Files (x86)\Mozilla Firefox\firefox.exe")) OR (SrcProcImagePath containsCIS "\AppData\Local\Flock\" AND SrcProcImagePath endswithCIS "\Flock.exe") OR (SrcProcImagePath In Contains AnyCase ("C:\Program Files (x86)\Internet Explorer\iexplore.exe","C:\Program Files\Internet Explorer\iexplore.exe")) OR (SrcProcImagePath containsCIS "\AppData\Local\Maxthon\" AND SrcProcImagePath endswithCIS "\maxthon.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\Programs\midori-ng\" AND SrcProcImagePath endswithCIS "\Midori Next Generation.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\Programs\Opera\" AND SrcProcImagePath endswithCIS "\opera.exe") OR (SrcProcImagePath containsCIS "\AppData\Local\Phoebe\" AND SrcProcImagePath endswithCIS "\Phoebe.exe") OR SrcProcImagePath endswithCIS "\safari.exe" OR (SrcProcImagePath endswithCIS "\seamonkey.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\SeaMonkey\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\SeaMonkey\")) OR (SrcProcImagePath endswithCIS "\slimbrowser.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\SlimBrowser\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\SlimBrowser\")) OR SrcProcImagePath containsCIS "\Tor Browser\" OR (SrcProcImagePath containsCIS "\AppData\Local\Vivaldi\" AND SrcProcImagePath endswithCIS "\vivaldi.exe") OR (SrcProcImagePath endswithCIS "\whale.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Naver\Naver Whale\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Naver\Naver Whale\")) OR (SrcProcImagePath endswithCIS "\Waterfox.exe" AND (SrcProcImagePath startswithCIS "C:\Program Files\Waterfox\" OR SrcProcImagePath startswithCIS "C:\Program Files (x86)\Waterfox\"))))))

```