# file_event_win_susp_pfx_file_creation

## Title
Suspicious PFX File Creation

## ID
dca1b3e8-e043-4ec8-85d7-867f334b5724

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-05-02

## Tags
attack.credential-access, attack.t1552.004

## Description
A general detection for processes creating PFX files. This could be an indicator of an adversary exporting a local certificate to a PFX file.

## References
https://github.com/OTRF/detection-hackathon-apt29/issues/14
https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/6.B.1_6392C9F1-D975-4F75-8A70-433DEDD7F622.md

## False Positives
System administrators managing certificates.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".pfx" AND (NOT (TgtFilePath containsCIS "\Templates\Windows\Windows_TemporaryKey.pfx" AND TgtFilePath containsCIS "\CMake\"))))

```