# proc_creation_win_powershell_susp_parameter_variation

## Title
Suspicious PowerShell Parameter Substring

## ID
36210e0d-5b19-485d-a087-c096088885f0

## Author
Florian Roth (Nextron Systems), Daniel Bohannon (idea), Roberto Rodriguez (Fix)

## Date
2019-01-16

## Tags
attack.execution, attack.t1059.001

## Description
Detects suspicious PowerShell invocation with a parameter substring

## References
http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -windowstyle h " OR TgtProcCmdLine containsCIS " -windowstyl h" OR TgtProcCmdLine containsCIS " -windowsty h" OR TgtProcCmdLine containsCIS " -windowst h" OR TgtProcCmdLine containsCIS " -windows h" OR TgtProcCmdLine containsCIS " -windo h" OR TgtProcCmdLine containsCIS " -wind h" OR TgtProcCmdLine containsCIS " -win h" OR TgtProcCmdLine containsCIS " -wi h" OR TgtProcCmdLine containsCIS " -win h " OR TgtProcCmdLine containsCIS " -win hi " OR TgtProcCmdLine containsCIS " -win hid " OR TgtProcCmdLine containsCIS " -win hidd " OR TgtProcCmdLine containsCIS " -win hidde " OR TgtProcCmdLine containsCIS " -NoPr " OR TgtProcCmdLine containsCIS " -NoPro " OR TgtProcCmdLine containsCIS " -NoProf " OR TgtProcCmdLine containsCIS " -NoProfi " OR TgtProcCmdLine containsCIS " -NoProfil " OR TgtProcCmdLine containsCIS " -nonin " OR TgtProcCmdLine containsCIS " -nonint " OR TgtProcCmdLine containsCIS " -noninte " OR TgtProcCmdLine containsCIS " -noninter " OR TgtProcCmdLine containsCIS " -nonintera " OR TgtProcCmdLine containsCIS " -noninterac " OR TgtProcCmdLine containsCIS " -noninteract " OR TgtProcCmdLine containsCIS " -noninteracti " OR TgtProcCmdLine containsCIS " -noninteractiv " OR TgtProcCmdLine containsCIS " -ec " OR TgtProcCmdLine containsCIS " -encodedComman " OR TgtProcCmdLine containsCIS " -encodedComma " OR TgtProcCmdLine containsCIS " -encodedComm " OR TgtProcCmdLine containsCIS " -encodedCom " OR TgtProcCmdLine containsCIS " -encodedCo " OR TgtProcCmdLine containsCIS " -encodedC " OR TgtProcCmdLine containsCIS " -encoded " OR TgtProcCmdLine containsCIS " -encode " OR TgtProcCmdLine containsCIS " -encod " OR TgtProcCmdLine containsCIS " -enco " OR TgtProcCmdLine containsCIS " -en " OR TgtProcCmdLine containsCIS " -executionpolic " OR TgtProcCmdLine containsCIS " -executionpoli " OR TgtProcCmdLine containsCIS " -executionpol " OR TgtProcCmdLine containsCIS " -executionpo " OR TgtProcCmdLine containsCIS " -executionp " OR TgtProcCmdLine containsCIS " -execution bypass" OR TgtProcCmdLine containsCIS " -executio bypass" OR TgtProcCmdLine containsCIS " -executi bypass" OR TgtProcCmdLine containsCIS " -execut bypass" OR TgtProcCmdLine containsCIS " -execu bypass" OR TgtProcCmdLine containsCIS " -exec bypass" OR TgtProcCmdLine containsCIS " -exe bypass" OR TgtProcCmdLine containsCIS " -ex bypass" OR TgtProcCmdLine containsCIS " -ep bypass" OR TgtProcCmdLine containsCIS " /windowstyle h " OR TgtProcCmdLine containsCIS " /windowstyl h" OR TgtProcCmdLine containsCIS " /windowsty h" OR TgtProcCmdLine containsCIS " /windowst h" OR TgtProcCmdLine containsCIS " /windows h" OR TgtProcCmdLine containsCIS " /windo h" OR TgtProcCmdLine containsCIS " /wind h" OR TgtProcCmdLine containsCIS " /win h" OR TgtProcCmdLine containsCIS " /wi h" OR TgtProcCmdLine containsCIS " /win h " OR TgtProcCmdLine containsCIS " /win hi " OR TgtProcCmdLine containsCIS " /win hid " OR TgtProcCmdLine containsCIS " /win hidd " OR TgtProcCmdLine containsCIS " /win hidde " OR TgtProcCmdLine containsCIS " /NoPr " OR TgtProcCmdLine containsCIS " /NoPro " OR TgtProcCmdLine containsCIS " /NoProf " OR TgtProcCmdLine containsCIS " /NoProfi " OR TgtProcCmdLine containsCIS " /NoProfil " OR TgtProcCmdLine containsCIS " /nonin " OR TgtProcCmdLine containsCIS " /nonint " OR TgtProcCmdLine containsCIS " /noninte " OR TgtProcCmdLine containsCIS " /noninter " OR TgtProcCmdLine containsCIS " /nonintera " OR TgtProcCmdLine containsCIS " /noninterac " OR TgtProcCmdLine containsCIS " /noninteract " OR TgtProcCmdLine containsCIS " /noninteracti " OR TgtProcCmdLine containsCIS " /noninteractiv " OR TgtProcCmdLine containsCIS " /ec " OR TgtProcCmdLine containsCIS " /encodedComman " OR TgtProcCmdLine containsCIS " /encodedComma " OR TgtProcCmdLine containsCIS " /encodedComm " OR TgtProcCmdLine containsCIS " /encodedCom " OR TgtProcCmdLine containsCIS " /encodedCo " OR TgtProcCmdLine containsCIS " /encodedC " OR TgtProcCmdLine containsCIS " /encoded " OR TgtProcCmdLine containsCIS " /encode " OR TgtProcCmdLine containsCIS " /encod " OR TgtProcCmdLine containsCIS " /enco " OR TgtProcCmdLine containsCIS " /en " OR TgtProcCmdLine containsCIS " /executionpolic " OR TgtProcCmdLine containsCIS " /executionpoli " OR TgtProcCmdLine containsCIS " /executionpol " OR TgtProcCmdLine containsCIS " /executionpo " OR TgtProcCmdLine containsCIS " /executionp " OR TgtProcCmdLine containsCIS " /execution bypass" OR TgtProcCmdLine containsCIS " /executio bypass" OR TgtProcCmdLine containsCIS " /executi bypass" OR TgtProcCmdLine containsCIS " /execut bypass" OR TgtProcCmdLine containsCIS " /execu bypass" OR TgtProcCmdLine containsCIS " /exec bypass" OR TgtProcCmdLine containsCIS " /exe bypass" OR TgtProcCmdLine containsCIS " /ex bypass" OR TgtProcCmdLine containsCIS " /ep bypass") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```