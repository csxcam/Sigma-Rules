# Sigma-Rules

Regla Sigma: Detectar intentos de deshabilitar AMSI mediante manipulación de memoria

Descripción:
Esta regla Sigma tiene como objetivo detectar intentos de deshabilitar el Módulo de Inspección de Script de Antimalware (AMSI) en sistemas Windows mediante manipulación de memoria en un proceso específico, como powershell.exe.

Escenario de detección:
El Módulo de Inspección de Script de Antimalware (AMSI) es una característica de seguridad en Windows que ayuda a proteger las aplicaciones de scripting al permitir que las aplicaciones y servicios soliciten que se escaneen secuencias de comandos antes de su ejecución. Esto ayuda a detectar y bloquear posibles secuencias de comandos maliciosas antes de que puedan ejecutarse.

Los atacantes pueden intentar deshabilitar AMSI para evitar su detección. Una de las técnicas comunes para deshabilitar AMSI es manipular la memoria de un proceso, como powershell.exe, para evitar que se realicen llamadas a la función AmsiScanBuffer que es utilizada por AMSI para escanear el contenido de scripts.

Detalles de la regla:
La regla Sigma utiliza eventos de Sysmon para detectar dos situaciones específicas:

    Selección 1 (EventID: 1): Detecta si el proceso powershell.exe realiza una llamada a la función GetProcAddress para obtener la dirección de memoria de la función AmsiScanBuffer dentro del archivo de biblioteca amsi.dll. Esta llamada puede ser un indicador de que el proceso está intentando localizar la función AmsiScanBuffer para manipularla.

    Selección 2 (EventID: 10): Detecta si el proceso powershell.exe intenta acceder al archivo de biblioteca amsi.dll con un permiso de acceso específico (0x40). Esto puede indicar que el proceso está tratando de realizar una modificación en la biblioteca amsi.dll, lo que podría ser un intento de deshabilitar AMSI.

Condición de detección:
La regla combina las selecciones 1 y 2 utilizando el operador lógico AND (condition: selection1 and selection2). Esto significa que ambas condiciones deben cumplirse para que se active la detección y se considere que ha ocurrido un intento de deshabilitar AMSI mediante manipulación de memoria.

Nivel de severidad:
Se ha asignado un nivel alto de severidad a esta regla debido a la importancia crítica de la característica AMSI en la protección contra scripts maliciosos. Si se detecta un intento de deshabilitar AMSI, puede indicar un intento activo de evadir la detección de amenazas y comprometer el sistema.

Recomendaciones:
Si esta regla Sigma se activa, se recomienda realizar una investigación exhaustiva del proceso y del sistema afectado. Se deben tomar medidas inmediatas para mitigar la amenaza y restaurar AMSI a su estado de funcionamiento normal. También es recomendable revisar y mejorar las medidas de seguridad y protección para evitar futuros intentos de deshabilitar AMSI u otras técnicas de evasión.
