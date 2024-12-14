# proc_creation_win_esentutl_webcache

## Title
Esentutl Steals Browser Information

## ID
6a69f62d-ce75-4b57-8dce-6351eb55b362

## Author
frack113

## Date
2022-02-13

## Tags
attack.collection, attack.t1005

## Description
One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe

## References
https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
https://redcanary.com/threat-detection-report/threats/qbot/
https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-r" OR TgtProcCmdLine containsCIS "/r" OR TgtProcCmdLine containsCIS "â€“r" OR TgtProcCmdLine containsCIS "â€”r" OR TgtProcCmdLine containsCIS "â€•r") AND TgtProcImagePath endswithCIS "\esentutl.exe" AND TgtProcCmdLine containsCIS "\Windows\WebCache"))

```