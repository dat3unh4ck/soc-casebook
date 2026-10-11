# CASO 01 — Compromiso del servidor web de Wayne Enterprises

| | |
|---|---|
| **ID** | CASE-2016-0810-001 |
| **Severidad** | Crítica (P1) |
| **Estado** | Cerrado — Verdadero Positivo |
| **Plataforma** | Splunk Enterprise (SPL) |
| **Dataset** | Splunk BOTS v1 — 955.807 eventos, 20 sourcetypes, 10–24 ago 2016 |
| **Frameworks** | MITRE ATT&CK v15 · NIST SP 800-61 Rev. 2 |

Ataque coordinado multifase del grupo hacktivista *po1s0n1vy* contra la infraestructura
web de Wayne Enterprises: escaneo automatizado, fuerza bruta, web shell y defacement.

📺 [Vídeo del caso en @DateUnH4ck](https://www.youtube.com/watch?v=mDertxflayg)

---

## 1. Alerta recibida

El IDS Suricata dispara `ET SCAN Acunetix Version 6 (Free Edition) Scan Detected`.
Origen `40.80.148.42` contra el servidor web `192.168.250.70`.

```spl
index=botsv1 earliest=0 sourcetype=suricata alert.signature=*
| stats count by alert.signature | sort -count
```

## 2. Triaje

```spl
index=botsv1 earliest=0 sourcetype=suricata "Acunetix"
| stats count by src_ip dest_ip
```

```spl
index=botsv1 earliest=0 sourcetype=suricata alert.signature="ET WEB_SERVER*"
| stats count by src_ip | sort -count
```

**Decisión:** Verdadero Positivo. Prioridad P1. Se escala a investigación completa.

## 3. Análisis de logs

### 3.1 Reconocimiento del entorno

```spl
index=botsv1 earliest=0 | stats count by sourcetype | sort -count
```

20 fuentes de datos, 955.807 eventos, rango 10–24 de agosto de 2016.

### 3.2 Timeline de alertas IDS

```spl
index=botsv1 earliest=0 sourcetype=suricata src_ip="40.80.148.42"
| stats min(_time) as inicio max(_time) as fin count by alert.signature
| eval inicio=strftime(inicio,"%Y-%m-%d %H:%M:%S")
| eval fin=strftime(fin,"%Y-%m-%d %H:%M:%S") | sort inicio
```

Ataque concentrado entre las 23:36 y las 00:21 del 10 de agosto. **50 firmas únicas**:
Acunetix, Shellshock, XSS, SQLi, ejecución de comandos y directory traversal.

### 3.3 Servidor web (IIS)

```spl
index=botsv1 earliest=0 sourcetype=iis c_ip="40.80.148.42"
| stats count by cs_uri_stem | sort -count | head 20
```

Servidor Joomla. El componente de búsqueda recibe **16.871 peticiones** (SQLi), el panel
de administración 35 accesos, y aparece una imagen `imnotbatman.jpg`.

```spl
index=botsv1 earliest=0 sourcetype=iis c_ip="40.80.148.42"
| stats count by sc_status | sort -count
```

De 20.967 peticiones: 6.292 con código 200 y 1.522 errores 500.

### 3.4 Compromiso del panel de administración

```spl
index=botsv1 earliest=0 sourcetype=iis c_ip="40.80.148.42"
  cs_uri_stem="/joomla/administrator/index.php"
| stats count by cs_method sc_status | sort -count
```

**Tres POST con código 303.** En Joomla, un 303 tras un POST de login es una redirección
post-autenticación: confirma el acceso exitoso. El atacante navega después a
`com_installer`, el instalador de extensiones, que es por donde entra el web shell.

### 3.5 Fuerza bruta

```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip="192.168.250.70"
  http_method=POST form_data=*username*passwd*
| stats count by src_ip
```

Aparece una **segunda IP**: `23.22.63.114`, con **412 intentos** contra el usuario `admin`
usando un diccionario estándar. La última contraseña probada es `rock` — la que funcionó.

### 3.6 Web shell — agent.php

`23.22.63.114` accede **193 veces** a `/joomla/agent.php`, el web shell subido por el
atacante. El primer acceso se produce a las 23:55:22, **7 minutos después de la subida**.
Son peticiones GET sin query string: un canal de control deliberadamente discreto.

### 3.7 Defacement

La imagen `imnotbatman.jpg` se sirve 13 veces. Declaración hacktivista, fase final del ataque.

## 4. Pivoteo entre fuentes

### 4.1 Firewall Fortigate — el hallazgo que define el caso

El IPS detectó **12.860 eventos maliciosos y permitió 12.851**. Estaba en modo solo
detección. Entre lo que detectó y dejó pasar está una **reverse shell**
(`MS.Windows.CMD.Reverse.Shell`) desde `23.22.63.114`.

La defensa funcionó: vio el ataque entero. Lo que falló fue la configuración.

### 4.2 Sysmon — brecha de visibilidad

Sysmon no registró la creación de `agent.php`. El web shell se escribió en el directorio
web sin dejar rastro en el endpoint: la cobertura de Sysmon no incluía esas rutas.

## 5. Mapeo MITRE ATT&CK

| Táctica | Técnica | ID |
|---|---|---|
| Reconnaissance | Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) |
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Initial Access | Valid Accounts: Local Accounts | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Persistence | Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| Execution | Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) |
| Impact | Defacement: External Defacement | [T1491.002](https://attack.mitre.org/techniques/T1491/002/) |

## 6. Veredicto

**Compromiso confirmado.** Cadena completa:

```
Escaneo Acunetix (40.80.148.42)
   → Fuerza bruta admin:rock (23.22.63.114)
   → Login en el panel de administración
   → Web shell vía com_installer
   → Reverse shell
   → Defacement
```

Dos IPs coordinadas con roles distintos: una escanea, otra explota. El hueco de
actividad administrativa entre las 23:47 y las 23:55 marca el traspaso entre ambas.

## 7. Contención recomendada

1. Aislar el servidor web y bloquear ambas IPs.
2. Cambiar credenciales y revocar todas las sesiones activas.
3. Eliminar `agent.php` y la extensión maliciosa instalada.
4. Restaurar desde copia de seguridad previa al 10 de agosto.
5. **Pasar el IPS de modo detección a modo prevención.**
6. Implementar MFA, WAF y rate-limiting en el panel de administración.
7. Ampliar la cobertura de Sysmon a los directorios web.

## 8. Lecciones aprendidas

El fallo no fue de detección, fue de configuración y de cobertura:

- **IPS en modo detección:** 12.851 eventos maliciosos permitidos, reverse shell incluida.
  Toda la telemetría estaba ahí; nadie la convirtió en bloqueo.
- **Contraseña débil:** `rock` cayó en 412 intentos, cuestión de segundos.
- **Sin anti-fuerza bruta:** 412 intentos consecutivos sin bloqueo ni retardo.
- **Sysmon incompleto:** el artefacto más importante del incidente —el web shell— no
  generó ningún evento de endpoint.

## 9. IOCs

| IOC | Tipo |
|---|---|
| `40.80.148.42` | IP atacante (escaneo) |
| `23.22.63.114` | IP atacante (fuerza bruta y web shell) |
| `/joomla/agent.php` | Web shell |
| `imnotbatman.jpg` | Artefacto de defacement |
| `admin:rock` | Credenciales comprometidas |

---

## Reproducir el caso

Dataset: **Splunk BOTS v1** (gratuito). El montaje completo del laboratorio —instalación de
Splunk, los 7 add-ons necesarios y la carga del dataset— está en
[`../docs/lab-setup.md`](../docs/lab-setup.md).
