# registry_set_susp_printer_driver

## Title
Suspicious Printer Driver Empty Manufacturer

## ID
e0813366-0407-449a-9869-a2db1119dc41

## Author
Florian Roth (Nextron Systems)

## Date
2020-07-01

## Tags
attack.privilege-escalation, attack.t1574, cve.2021-1675

## Description
Detects a suspicious printer driver installation with an empty Manufacturer value

## References
https://twitter.com/SBousseaden/status/1410545674773467140

## False Positives
Alerts on legitimate printer drivers that do not set any more details in the Manufacturer value

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "(Empty)" AND (RegistryKeyPath containsCIS "\Control\Print\Environments\Windows x64\Drivers" AND RegistryKeyPath containsCIS "\Manufacturer")) AND (NOT (RegistryKeyPath containsCIS "\CutePDF Writer v4.0\" OR RegistryKeyPath containsCIS "\Version-3\PDF24\" OR (RegistryKeyPath containsCIS "\VNC Printer (PS)\" OR RegistryKeyPath containsCIS "\VNC Printer (UD)\")))))

```