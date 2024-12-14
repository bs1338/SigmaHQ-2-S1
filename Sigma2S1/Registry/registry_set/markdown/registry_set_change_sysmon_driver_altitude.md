# registry_set_change_sysmon_driver_altitude

## Title
Sysmon Driver Altitude Change

## ID
4916a35e-bfc4-47d0-8e25-a003d7067061

## Author
B.Talebi

## Date
2022-07-28

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects changes in Sysmon driver altitude value.
If the Sysmon driver is configured to load at an altitude of another registered service, it will fail to load at boot.


## References
https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650
https://youtu.be/zSihR3lTf7g

## False Positives
Legitimate driver altitude change to hide sysmon

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Services\" AND RegistryKeyPath endswithCIS "\Instances\Sysmon Instance\Altitude"))

```