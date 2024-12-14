# proc_creation_win_susp_archiver_iso_phishing

## Title
Phishing Pattern ISO in Archive

## ID
fcdf69e5-a3d3-452a-9724-26f2308bf2b1

## Author
Florian Roth (Nextron Systems)

## Date
2022-06-07

## Tags
attack.initial-access, attack.t1566

## Description
Detects cases in which an ISO files is opend within an archiver like 7Zip or Winrar, which is a sign of phishing as threat actors put small ISO files in archives as email attachments to bypass certain filters and protective measures (mark of web)

## References
https://twitter.com/1ZRR4H/status/1534259727059787783
https://app.any.run/tasks/e1fe6a62-bce8-4323-a49a-63795d9afd5d/

## False Positives
Legitimate cases in which archives contain ISO or IMG files and the user opens the archive and the image via clicking and not extraction

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\isoburn.exe" OR TgtProcImagePath endswithCIS "\PowerISO.exe" OR TgtProcImagePath endswithCIS "\ImgBurn.exe") AND (SrcProcImagePath endswithCIS "\Winrar.exe" OR SrcProcImagePath endswithCIS "\7zFM.exe" OR SrcProcImagePath endswithCIS "\peazip.exe")))

```