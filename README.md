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
- Información sobre AMSI: https://docs.microsoft.com/en-us/windows/whats-new/whats-new-windows-10-21h1#antimalware-scan-interface-amsi-in-c-and-net
- Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

