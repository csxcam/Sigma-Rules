# Regla Sigma: Detect AMSI Disabling and Obfuscation via Memory Manipulation

**Descripción:**
Esta regla Sigma está diseñada para detectar intentos de deshabilitar AMSI (Anti-Malware Scan Interface) mediante la manipulación de la memoria en un proceso y el uso de técnicas de ofuscación en PowerShell. AMSI es una característica de seguridad en Windows que permite a las aplicaciones y herramientas de seguridad escanear y detectar contenido malicioso o sospechoso antes de su ejecución, lo que ayuda a proteger contra amenazas de malware.

**Detalles de la Regla:**
- La regla se basa en eventos de Sysmon (System Monitor) proporcionados por Windows.
- Detecta dos escenarios diferentes:
  1. Intentos de deshabilitar AMSI manipulando la memoria de un proceso, identificando la carga de la librería "amsi.dll" y llamadas a "GetProcAddress" en "powershell.exe".
  2. Uso de técnicas de ofuscación en PowerShell, detectando el uso de parámetros como "-EncodedCommand" y "-e" en "powershell.exe" que a menudo se emplean para ocultar comandos maliciosos.

**Nivel de Severidad:**
Alto

**Estado:**
Experimental

**Plataforma:**
- Windows
- Sysmon

**Uso:**
Esta regla puede implementarse en un entorno de seguridad para la detección temprana de intentos de deshabilitar AMSI y el uso de técnicas de ofuscación en PowerShell. Al detectar estos comportamientos, los administradores de seguridad pueden tomar medidas preventivas para evitar posibles ataques de malware.

**Autor:**
Camilo Burgos

**Fecha:**
27 de julio de 2023

**Aviso Legal:**
El uso de esta regla Sigma es responsabilidad del usuario y se debe aplicar según las políticas y regulaciones de seguridad establecidas en el entorno específico. Se recomienda probar la regla en un ambiente de pruebas antes de implementarla en producción.

**Referencias:**
- Información sobre AMSI: [https://docs.microsoft.com/en-us/windows/whats-new/whats-new-windows-10-21h1#antimalware-scan-interface-amsi-in-c-and-net](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon


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

