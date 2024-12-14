# file_event_win_office_outlook_rdp_file_creation

## Title
.RDP File Created by Outlook Process

## ID
f748c45a-f8d3-4e6f-b617-fe176f695b8f

## Author
Florian Roth

## Date
2024-11-01

## Tags
attack.defense-evasion

## Description
Detects the creation of files with the ".rdp" extensions in the temporary directory that Outlook uses when opening attachments.
This can be used to detect spear-phishing campaigns that use RDP files as attachments.


## References
https://thecyberexpress.com/rogue-rdp-files-used-in-ukraine-cyberattacks/
https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/
https://www.linkedin.com/feed/update/urn:li:ugcPost:7257437202706493443?commentUrn=urn%3Ali%3Acomment%3A%28ugcPost%3A7257437202706493443%2C7257522819985543168%29&dashCommentUrn=urn%3Ali%3Afsd_comment%3A%287257522819985543168%2Curn%3Ali%3AugcPost%3A7257437202706493443%29

## False Positives
Whenever someone receives an RDP file as an email attachment and decides to save or open it right from the attachments

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".rdp" AND ((TgtFilePath containsCIS "\AppData\Local\Packages\Microsoft.Outlook_" OR TgtFilePath containsCIS "\AppData\Local\Microsoft\Olk\Attachments\") OR (TgtFilePath containsCIS "\AppData\Local\Microsoft\Windows\" AND TgtFilePath containsCIS "\Content.Outlook\"))))

```