# registry_set_persistence_app_cpmpat_layer_registerapprestart

## Title
Potential Persistence Via AppCompat RegisterAppRestart Layer

## ID
b86852fb-4c77-48f9-8519-eb1b2c308b59

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-01-01

## Tags
attack.persistence, attack.t1546.011

## Description
Detects the setting of the REGISTERAPPRESTART compatibility layer on an application.
This compatibility layer allows an application to register for restart using the "RegisterApplicationRestart" API.
This can be potentially abused as a persistence mechanism.


## References
https://github.com/nasbench/Misc-Research/blob/d114d6a5e0a437d3818e492ef9864367152543e7/Other/Persistence-Via-RegisterAppRestart-Shim.md

## False Positives
Legitimate applications making use of this feature for compatibility reasons

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue containsCIS "REGISTERAPPRESTART" AND RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers\"))

```