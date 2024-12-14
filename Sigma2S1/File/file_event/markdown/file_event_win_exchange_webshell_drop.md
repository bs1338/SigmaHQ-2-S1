# file_event_win_exchange_webshell_drop

## Title
Suspicious ASPX File Drop by Exchange

## ID
bd1212e5-78da-431e-95fa-c58e3237a8e6

## Author
Florian Roth (Nextron Systems), MSTI (query, idea)

## Date
2022-10-01

## Tags
attack.persistence, attack.t1505.003

## Description
Detects suspicious file type dropped by an Exchange component in IIS into a suspicious folder

## References
https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/
https://www.gteltsc.vn/blog/canh-bao-chien-dich-tan-cong-su-dung-lo-hong-zero-day-tren-microsoft-exchange-server-12714.html
https://en.gteltsc.vn/blog/cap-nhat-nhe-ve-lo-hong-bao-mat-0day-microsoft-exchange-dang-duoc-su-dung-de-tan-cong-cac-to-chuc-tai-viet-nam-9685.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcCmdLine containsCIS "MSExchange" AND SrcProcImagePath endswithCIS "\w3wp.exe" AND (TgtFilePath containsCIS "FrontEnd\HttpProxy\" OR TgtFilePath containsCIS "\inetpub\wwwroot\aspnet_client\")) AND (TgtFilePath endswithCIS ".aspx" OR TgtFilePath endswithCIS ".asp" OR TgtFilePath endswithCIS ".ashx")))

```