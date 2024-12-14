# registry_event_narrator_feedback_persistance

## Title
Narrator's Feedback-Hub Persistence

## ID
f663a6d9-9d1b-49b8-b2b1-0637914d199a

## Author
Dmitriy Lifanov, oscd.community

## Date
2019-10-25

## Tags
attack.persistence, attack.t1547.001

## Description
Detects abusing Windows 10 Narrator's Feedback-Hub

## References
https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((EventType = "DeleteValue" AND RegistryKeyPath endswithCIS "\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\DelegateExecute") OR RegistryKeyPath endswithCIS "\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\(Default)"))

```