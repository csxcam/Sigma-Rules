# Sigma Rule: Detect AMSI Disabling and Obfuscation via Memory Manipulation

## Description
This Sigma rule is designed to detect attempts to disable AMSI (Anti-Malware Scan Interface) through memory manipulation in a process and the use of obfuscation techniques in PowerShell. AMSI is a security feature in Windows that allows applications and security tools to scan and detect malicious or suspicious content before execution, helping to protect against malware threats.

## Rule Details
The rule is based on Sysmon (System Monitor) events provided by Windows.
It detects two different scenarios:
1. Attempts to disable AMSI by manipulating the memory of a process, identifying the loading of the "amsi.dll" library, and calls to "GetProcAddress" in "powershell.exe".
2. Use of obfuscation techniques in PowerShell, detecting the use of parameters like "-EncodedCommand" and "-e" in "powershell.exe" that are often used to conceal malicious commands.

## Severity Level: High
## Status: Experimental
## Platform:
- Windows
- Sysmon

## Usage
This rule can be implemented in a security environment for early detection of attempts to disable AMSI and the use of obfuscation techniques in PowerShell. By detecting these behaviors, security administrators can take preventive measures to avoid potential malware attacks.

## Author: Camilo Burgos
## Date: July 27, 2023

## Disclaimer
The use of this Sigma rule is the responsibility of the user and should be applied according to the security policies and regulations established in the specific environment. It is recommended to test the rule in a test environment before deploying it in production.

## References
- Information about AMSI: https://docs.microsoft.com/en-us/windows/whats-new/whats-new-windows-10-21h1#antimalware-scan-interface-amsi-in-c-and-net
- Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

Note: This Sigma rule is provided for GitHub use. If you need further assistance or have more questions, feel free to ask. I'm here to help!



## # Enhanced Detection of Suspicious Use of mshta.exe to Execute Binary

This Sigma rule detects suspicious use of mshta.exe to execute binary content with an expanded set of patterns, targeting specific techniques and polyglotism.

## Rule Information

- **Title**: Enhanced Detection of Suspicious Use of mshta.exe to Execute Binary
- **Author**: Camilo Burgos
- **Date**: 2023-07-28
- **Status**: Stable
- **Level**: High
- **Tags**: attack.defense_evasion, attack.t1140

## Description

The rule leverages Sysmon data and searches for events with `EventID: 1`, which indicates process creations. It targets the execution of `mshta.exe` and checks for specific patterns in the command line that might be indicative of suspicious behavior. The rule looks for the following patterns in the command line:

- Presence of `vbscript`
- Suspicious use of image files (e.g., `*.jpg*`, `*.png*`)
- Execution of .lnk (shortcut) files
- Execution of Excel and Word files (e.g., `*.xls*`, `*.doc*`)
- Use of zip archives (e.g., `*.zip*`)
- Command lines involving HTTP (potential network activity)
- Command lines involving JavaScript
- Command lines containing the word "script"
- Specific mshta.exe technique with `ActiveXObject`, which could indicate malicious activities

The rule is marked with a high severity level, indicating its importance in detecting potentially malicious behavior related to mshta.exe. Please be aware that there might be false positives based on legitimate scripts and administrative tools used in your monitored environment. Regularly review and fine-tune the rule to adapt it to the normal behavior of your environment.

## References

- [Microsoft Security Blog - Threat Actors Misusing mshta.exe](https://www.microsoft.com/security/blog/2023/07/15/threat-actors-misusing-mshta-exe/)
- [MITRE ATT&CK - T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

## False Positives

False positives may occur based on legitimate scripts and administrative tools used in the monitored environment. Regularly review and fine-tune the rule based on your environment's normal behavior.


# Sigma Rule: Rundll32.exe Abused for Proxy Execution of Malicious Code

## Description
This Sigma rule detects attempts to abuse rundll32.exe for proxy execution of malicious code, including executing DLL payloads, Control Panel Item files (.cpl), and scripts like JavaScript. Adversaries may utilize rundll32.exe to evade security tools that do not monitor its execution due to allowlists or false positives from normal operations. They may also obscure malicious code by appending W and/or A to exported function names or using ordinal numbers for execution. Additionally, masquerading techniques, such as changing DLL file names, extensions, or function names, can further conceal the payload.

## Detection Details
The rule leverages Sysmon (System Monitor) events on Windows. It consists of two different detection scenarios:
1. Detects rundll32.exe execution with DLL or .cpl files and specific undocumented shell32.dll functions.
2. Detects rundll32.exe execution with function names appended with W, A, or ordinal numbers.

## Severity Level: High
## Status: Experimental
## Platform:
- Windows
- Sysmon

## False Positives
Legitimate use of rundll32.exe for system operations and software installations may trigger false positives.

## Author: Camilo Burgos
## Date: 2023-07-28

## References
- Information about AMSI: https://docs.microsoft.com/en-us/windows/whats-new/whats-new-windows-10-21h1#antimalware-scan-interface-amsi-in-c-and-net
- Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

Disclaimer: The use of this Sigma rule is the responsibility of the user and should be applied according to the security policies and regulations established in the specific environment. It is recommended to test the rule in a test environment before deploying it in production.



