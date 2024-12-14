# proc_creation_win_susp_browser_launch_from_document_reader_process

## Title
Potential Suspicious Browser Launch From Document Reader Process

## ID
1193d960-2369-499f-a158-7b50a31df682

## Author
Joseph Kamau

## Date
2024-05-27

## Tags
attack.execution, attack.t1204.002

## Description
Detects when a browser process or browser tab is launched from an application that handles document files such as Adobe, Microsoft Office, etc. And connects to a web application over http(s), this could indicate a possible phishing attempt.


## References
https://app.any.run/tasks/69c5abaa-92ad-45ba-8c53-c11e23e05d04/
https://app.any.run/tasks/64043a79-165f-4052-bcba-e6e49f847ec1/

## False Positives
Unlikely in most cases, further investigation should be done in the commandline of the browser process to determine the context of the URL accessed.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "http" AND (TgtProcImagePath endswithCIS "\brave.exe" OR TgtProcImagePath endswithCIS "\chrome.exe" OR TgtProcImagePath endswithCIS "\firefox.exe" OR TgtProcImagePath endswithCIS "\msedge.exe" OR TgtProcImagePath endswithCIS "\opera.exe" OR TgtProcImagePath endswithCIS "\maxthon.exe" OR TgtProcImagePath endswithCIS "\seamonkey.exe" OR TgtProcImagePath endswithCIS "\vivaldi.exe" OR TgtProcImagePath startswithCIS "") AND (SrcProcImagePath containsCIS "Acrobat Reader" OR SrcProcImagePath containsCIS "Microsoft Office" OR SrcProcImagePath containsCIS "PDF Reader")))

```