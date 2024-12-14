# registry_event_susp_download_run_key

## Title
Suspicious Run Key from Download

## ID
9c5037d1-c568-49b3-88c7-9846a5bdc2be

## Author
Florian Roth (Nextron Systems)

## Date
2019-10-01

## Tags
attack.persistence, attack.t1547.001

## Description
Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories

## References
https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/

## False Positives
Software installers downloaded and used by users

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((SrcProcImagePath containsCIS "\Downloads\" OR SrcProcImagePath containsCIS "\Temporary Internet Files\Content.Outlook\" OR SrcProcImagePath containsCIS "\Local Settings\Temporary Internet Files\") AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"))

```