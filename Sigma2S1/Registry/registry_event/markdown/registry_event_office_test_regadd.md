# registry_event_office_test_regadd

## Title
Office Application Startup - Office Test

## ID
3d27f6dd-1c74-4687-b4fa-ca849d128d1c

## Author
omkar72

## Date
2020-10-25

## Tags
attack.persistence, attack.t1137.002

## Description
Detects the addition of office test registry that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started

## References
https://unit42.paloaltonetworks.com/unit42-technical-walkthrough-office-test-persistence-method-used-in-recent-sofacy-attacks/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\Software\Microsoft\Office test\Special\Perf")

```