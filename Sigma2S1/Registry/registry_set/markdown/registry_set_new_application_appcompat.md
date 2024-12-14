# registry_set_new_application_appcompat

## Title
New Application in AppCompat

## ID
60936b49-fca0-4f32-993d-7415edcf9a5d

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-05-02

## Tags
attack.execution, attack.t1204.002

## Description
A General detection for a new application in AppCompat. This indicates an application executing for the first time on an endpoint.

## References
https://github.com/OTRF/detection-hackathon-apt29/issues/1
https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/1.A.1_DFD6A782-9BDB-4550-AB6B-525E825B095E.md

## False Positives
This rule is to explore new applications on an endpoint. False positives depends on the organization.
Newly setup system.
Legitimate installation of new application.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\AppCompatFlags\Compatibility Assistant\Store\")

```