# registry_set_cobaltstrike_service_installs

## Title
Potential CobaltStrike Service Installations - Registry

## ID
61a7697c-cb79-42a8-a2ff-5f0cdfae0130

## Author
Wojciech Lesicki

## Date
2021-06-29

## Tags
attack.execution, attack.privilege-escalation, attack.lateral-movement, attack.t1021.002, attack.t1543.003, attack.t1569.002

## Description
Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement.


## References
https://www.sans.org/webcasts/tech-tuesday-workshop-cobalt-strike-detection-log-analysis-119395

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryValue containsCIS "ADMIN$" AND RegistryValue containsCIS ".exe") OR (RegistryValue containsCIS "%COMSPEC%" AND RegistryValue containsCIS "start" AND RegistryValue containsCIS "powershell")) AND (RegistryKeyPath containsCIS "\System\CurrentControlSet\Services" OR (RegistryKeyPath containsCIS "\System\ControlSet" AND RegistryKeyPath containsCIS "\Services"))))

```