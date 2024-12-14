# proc_creation_win_susp_double_extension_parent

## Title
Suspicious Parent Double Extension File Execution

## ID
5e6a80c8-2d45-4633-9ef4-fa2671a39c5c

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-06

## Tags
attack.defense-evasion, attack.t1036.007

## Description
Detect execution of suspicious double extension files in ParentCommandLine

## References
https://www.virustotal.com/gui/file/7872d8845a332dce517adae9c3389fde5313ff2fed38c2577f3b498da786db68/behavior
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bluebottle-banks-targeted-africa

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS ".doc.lnk" OR SrcProcImagePath endswithCIS ".docx.lnk" OR SrcProcImagePath endswithCIS ".xls.lnk" OR SrcProcImagePath endswithCIS ".xlsx.lnk" OR SrcProcImagePath endswithCIS ".ppt.lnk" OR SrcProcImagePath endswithCIS ".pptx.lnk" OR SrcProcImagePath endswithCIS ".rtf.lnk" OR SrcProcImagePath endswithCIS ".pdf.lnk" OR SrcProcImagePath endswithCIS ".txt.lnk" OR SrcProcImagePath endswithCIS ".doc.js" OR SrcProcImagePath endswithCIS ".docx.js" OR SrcProcImagePath endswithCIS ".xls.js" OR SrcProcImagePath endswithCIS ".xlsx.js" OR SrcProcImagePath endswithCIS ".ppt.js" OR SrcProcImagePath endswithCIS ".pptx.js" OR SrcProcImagePath endswithCIS ".rtf.js" OR SrcProcImagePath endswithCIS ".pdf.js" OR SrcProcImagePath endswithCIS ".txt.js") OR (SrcProcCmdLine containsCIS ".doc.lnk" OR SrcProcCmdLine containsCIS ".docx.lnk" OR SrcProcCmdLine containsCIS ".xls.lnk" OR SrcProcCmdLine containsCIS ".xlsx.lnk" OR SrcProcCmdLine containsCIS ".ppt.lnk" OR SrcProcCmdLine containsCIS ".pptx.lnk" OR SrcProcCmdLine containsCIS ".rtf.lnk" OR SrcProcCmdLine containsCIS ".pdf.lnk" OR SrcProcCmdLine containsCIS ".txt.lnk" OR SrcProcCmdLine containsCIS ".doc.js" OR SrcProcCmdLine containsCIS ".docx.js" OR SrcProcCmdLine containsCIS ".xls.js" OR SrcProcCmdLine containsCIS ".xlsx.js" OR SrcProcCmdLine containsCIS ".ppt.js" OR SrcProcCmdLine containsCIS ".pptx.js" OR SrcProcCmdLine containsCIS ".rtf.js" OR SrcProcCmdLine containsCIS ".pdf.js" OR SrcProcCmdLine containsCIS ".txt.js")))

```