# registry_set_clickonce_trust_prompt

## Title
ClickOnce Trust Prompt Tampering

## ID
ac9159cc-c364-4304-8f0a-d63fc1a0aabb

## Author
@SerkinValery, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-12

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects changes to the ClickOnce trust prompt registry key in order to enable an installation from different locations such as the Internet.

## References
https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
https://learn.microsoft.com/en-us/visualstudio/deployment/how-to-configure-the-clickonce-trust-prompt-behavior

## False Positives
Legitimate internal requirements.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "Enabled" AND RegistryKeyPath containsCIS "\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel\" AND (RegistryKeyPath endswithCIS "\Internet" OR RegistryKeyPath endswithCIS "\LocalIntranet" OR RegistryKeyPath endswithCIS "\MyComputer" OR RegistryKeyPath endswithCIS "\TrustedSites" OR RegistryKeyPath endswithCIS "\UntrustedSites")))

```