# registry_set_uac_disable_secure_desktop_prompt

## Title
UAC Secure Desktop Prompt Disabled

## ID
0d7ceeef-3539-4392-8953-3dc664912714

## Author
frack113

## Date
2024-05-10

## Tags
attack.privilege-escalation, attack.defense-evasion, attack.t1548.002

## Description
Detects when an attacker tries to change User Account Control (UAC) elevation request destination via the "PromptOnSecureDesktop" value.
The "PromptOnSecureDesktop" setting specifically determines whether UAC prompts are displayed on the secure desktop. The secure desktop is a separate desktop environment that's isolated from other processes running on the system. It's designed to prevent malicious software from intercepting or tampering with UAC prompts.
When "PromptOnSecureDesktop" is set to 0, UAC prompts are displayed on the user's current desktop instead of the secure desktop. This reduces the level of security because it potentially exposes the prompts to manipulation by malicious software.


## References
https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop"))

```