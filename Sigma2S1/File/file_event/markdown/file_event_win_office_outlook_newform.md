# file_event_win_office_outlook_newform

## Title
Potential Persistence Via Outlook Form

## ID
c3edc6a5-d9d4-48d8-930e-aab518390917

## Author
Tobias Michalski (Nextron Systems)

## Date
2021-06-10

## Tags
attack.persistence, attack.t1137.003

## Description
Detects the creation of a new Outlook form which can contain malicious code

## References
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=76
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=79
https://learn.microsoft.com/en-us/office/vba/outlook/concepts/outlook-forms/create-an-outlook-form
https://www.slipstick.com/developer/custom-form/clean-outlooks-forms-cache/

## False Positives
Legitimate use of outlook forms

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\outlook.exe" AND (TgtFilePath containsCIS "\AppData\Local\Microsoft\FORMS\IPM" OR TgtFilePath containsCIS "\Local Settings\Application Data\Microsoft\Forms")))

```