# proc_creation_win_msdt_susp_cab_options

## Title
Suspicious Cabinet File Execution Via Msdt.EXE

## ID
dc4576d4-7467-424f-9eee-fd2b02855fe0

## Author
Nasreddine Bencherchali (Nextron Systems), GossiTheDog, frack113

## Date
2022-06-21

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects execution of msdt.exe using the "cab" flag which could indicates suspicious diagcab files with embedded answer files leveraging CVE-2022-30190

## References
https://twitter.com/nas_bench/status/1537896324837781506
https://github.com/GossiTheDog/ThreatHunting/blob/e85884abbf05d5b41efc809ea6532b10b45bd05c/AdvancedHuntingQueries/DogWalk-DiagCab
https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-9015912909545e72ed42cbac4d1e96295e8964579c406d23fd9c47a8091576a0
https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd

## False Positives
Legitimate usage of ".diagcab" files

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -cab " OR TgtProcCmdLine containsCIS " /cab " OR TgtProcCmdLine containsCIS " â€“cab " OR TgtProcCmdLine containsCIS " â€”cab " OR TgtProcCmdLine containsCIS " â€•cab ") AND TgtProcImagePath endswithCIS "\msdt.exe"))

```