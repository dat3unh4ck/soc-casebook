# Montaje de los laboratorios

Los tres casos usan datasets públicos y gratuitos. Ninguno requiere tarjeta de crédito.

---

## Caso 01 — Splunk BOTS v1

El más pesado de los tres: hay que instalar Splunk y siete add-ons.

**Requisitos:** 16 GB de RAM y 20 GB libres de disco (Splunk ~3 GB + dataset ~1 GB
descomprimido + espacio de indexación).

> En Apple Silicon no hay binario nativo: se instala la versión Intel y macOS la ejecuta
> bajo Rosetta. Splunk para Linux solo soporta x86_64, así que una VM ARM64 no sirve.

### 1. Instalar Splunk Enterprise

Descargar de [splunk.com](https://www.splunk.com/en_us/download/splunk-enterprise.html)
(cuenta gratuita), ejecutar el instalador y crear el usuario administrador cuando lo pida.
Después, entrar en **http://localhost:8000**.

### 2. Cambiar a licencia Free

La licencia Trial caduca a los 60 días. Para un laboratorio permanente:
**Settings → Licensing → Change license group → Free license → Save**, y reiniciar.

> Con la licencia Free se desactiva la autenticación. En local no importa, pero no
> expongas ese puerto.

### 3. Descargar el dataset

```bash
mkdir -p ~/Downloads/bots && cd ~/Downloads/bots
curl -L -o botsv1-attack-only.tgz \
  https://s3.amazonaws.com/botsdataset/botsv1/botsv1-attack-only.tgz
tar -xzf botsv1-attack-only.tgz -C /Applications/Splunk/etc/apps/
```

Se usa la versión *attack-only* (~135 MB) en vez del dataset completo: contiene los
eventos relevantes y pesa una fracción.

### 4. Instalar los add-ons

Sin ellos la extracción de campos no funciona y las consultas no devuelven nada. Se
descargan de Splunkbase y se extraen en la carpeta de apps:

| Add-on | App ID |
|---|---|
| Fortinet Fortigate Add-on | [2846](https://splunkbase.splunk.com/app/2846) |
| Splunk Add-on for Tenable | [1710](https://splunkbase.splunk.com/app/1710) |
| Splunk Add-on for Stream | [1809](https://splunkbase.splunk.com/app/1809) |
| Splunk Add-on for Microsoft Windows | [742](https://splunkbase.splunk.com/app/742) |
| CCX Add-on for Suricata | [6994](https://splunkbase.splunk.com/app/6994) |
| Microsoft Sysmon Add-on | [1914](https://splunkbase.splunk.com/app/1914) |
| URL Toolbox | [2734](https://splunkbase.splunk.com/app/2734) |

> El TA-Suricata original (app 2760) está archivado. El CCX Add-on (6994) es su
> reemplazo y aporta las mismas extracciones compatibles con CIM.

Con licencia Free no se pueden instalar apps desde la interfaz web. Se hace por terminal:

```bash
cd ~/Downloads/bots
for f in *.tgz *.spl; do sudo tar -xzf "$f" -C /Applications/Splunk/etc/apps/; done
/Applications/Splunk/bin/splunk restart
```

Los ficheros `.spl` son `.tgz` renombrados: `tar` los extrae igual.

### 5. Verificar

```spl
index=botsv1 earliest=0 | stats count
```

Debe devolver **955.807 eventos**. Si sale ese número, el laboratorio está listo.

---

## Caso 02 — CyberDefenders: Tomcat Takeover

**Requisitos:** Wireshark. Nada más. Viene preinstalado en Kali; en otros sistemas,
`sudo apt install wireshark -y` o la descarga oficial.

1. Crear cuenta gratuita en [cyberdefenders.org](https://cyberdefenders.org).
2. Abrir el challenge
   [Tomcat Takeover](https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/)
   y leer el escenario antes de empezar.
3. **Download Lab Files.** El ZIP está protegido; la contraseña aparece bajo el botón de
   descarga y es `cyberdefenders.org`:

```bash
cd ~/Downloads
unzip -P cyberdefenders.org 135-TomcatTakeover.zip
wireshark ~/Downloads/135-TomcatTakeover/*.pcap &
```

El PCAP tiene **21.070 paquetes**. Antes de filtrar nada, pasar por
**Statistics → Protocol Hierarchy**, **Conversations** y **Endpoints**.

---

## Caso 03 — KC7: Jojo's Hospital

El más accesible: **solo navegador**. No hace falta VM ni instalar nada.

1. Crear cuenta gratuita en [kc7cyber.com](https://kc7cyber.com) con una cuenta de
   Microsoft (necesaria para Azure Data Explorer).
2. **Game Vault → Jojo's Hospital: A Ransomware Investigation → Start Playing.**
3. KC7 conecta automáticamente con un clúster de ADX
   (`kc7001.eastus.JoJosHospital`) con las tablas `Employees`, `FileCreationEvents`,
   `ProcessEvents`, `InboundNetworkEvents`, `OutboundNetworkEvents`,
   `AuthenticationEvents` y `PassiveDns`.

Son 61 challenges y unas 2 h 30 min. El módulo requiere haber completado antes
*A Rap Beef* para desbloquearse.

---

## Nota sobre los datasets

Los tres son escenarios de entrenamiento públicos y ampliamente conocidos. Lo que
distingue a una investigación de otra no es el dataset, sino el método: qué se pregunta,
en qué orden, y qué se concluye de lo que **no** aparece en los logs.
