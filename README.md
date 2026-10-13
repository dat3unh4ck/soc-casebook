# SOC Casebook — investigaciones de incidentes de extremo a extremo

Tres investigaciones de incidentes de seguridad que hice de principio a fin, cada
una desde la alerta inicial hasta el veredicto y la escalación, siguiendo NIST SP
800-61 Rev. 2 y con mapeo a MITRE ATT&CK.

Lo que me interesaba documentar no es el manejo de las consolas —eso se aprende en
una tarde—, sino el razonamiento: decidir en minutos si una alerta es real, saber
qué preguntarle a los datos y saber cuándo escalar. Eso es lo que recojo aquí.

| # | Caso | Plataforma | Qué investigo |
|---|---|---|---|
| 01 | [Compromiso web — Wayne Enterprises](cases/01-wayne-enterprises-web-compromise.md) | Splunk (SPL) | Escaneo → fuerza bruta → web shell → defacement |
| 02 | [Apache Tomcat Takeover](cases/02-apache-tomcat-takeover.md) | Wireshark (PCAP) | Escaneo → enumeración → WAR malicioso → persistencia cron |
| 03 | [Ransomware en Jojo's Hospital](cases/03-jojos-hospital-ransomware.md) | Azure Data Explorer (KQL) | Malvertising → Cobalt Strike → venta de acceso → doble extorsión |

Los tres parten de datasets públicos y gratuitos: Splunk BOTS v1, CyberDefenders y
KC7. El montaje de cada laboratorio está en [`docs/lab-setup.md`](docs/lab-setup.md).

## Metodología

Cada caso recorre el mismo flujo, el que sigo como analista:

```
Alerta → Triaje → Análisis de logs → Pivoteo entre fuentes
      → Enriquecimiento de IOCs → Mapeo ATT&CK → Veredicto
      → Contención → Lecciones aprendidas
```

En el triaje decido verdadero o falso positivo con indicadores explícitos, no por
intuición. En el pivoteo cruzo fuentes distintas: lo que un log no cuenta, suele
contarlo otro. Las lecciones aprendidas las escribo autocríticas a propósito, porque
lo que me importa de un write-up es lo que deja ver sobre la defensa, más que la
narración del ataque.

## Qué saqué de cada caso

**Caso 01 — el IPS que lo vio todo y no bloqueó nada.** El hallazgo no fue el web
shell: fue que el Fortigate detectó 12.860 eventos maliciosos y permitió 12.851,
reverse shell incluida. Estaba en modo detección. Toda la telemetría existía; nadie
la había convertido en bloqueo. A eso se sumó una brecha de visibilidad: Sysmon no
registró la creación de `agent.php` porque su cobertura no incluía los directorios
web.

**Caso 02 — una investigación completa sin SIEM.** Sin logs de endpoint ni plataforma
de correlación, solo un PCAP. Del análisis de red saqué el escaneo, la herramienta de
enumeración (por el User-Agent `gobuster/3.6`), las credenciales en claro —HTTP Basic
es Base64, no cifrado—, el fichero subido y los comandos del atacante leídos del TCP
stream. El cambio de User-Agent entre fases delató además que había un operador humano
detrás de las herramientas.

**Caso 03 — 47 días de Cobalt Strike sin detección.** El dato que define el incidente
no es el ransomware, es el tiempo: entre la primera infección (01/05) y el cifrado
(17/06) pasaron 47 días con un beacon activo. Y el acceso inicial no fue técnico, fue
un anuncio patrocinado con typosquatting. Un pivote sobre PassiveDNS destapó
infraestructura que no aparecía en ningún log del hospital.

## Contenido

```
.
├── cases/                        Las tres investigaciones completas
├── queries/
│   ├── splunk-spl.md             Consultas SPL reutilizables, con el razonamiento
│   ├── kusto-kql.md              Consultas KQL para ADX y Sentinel
│   └── wireshark-filters.md      Filtros de display y qué revela cada uno
├── iocs/iocs.csv                 Los 25 IOCs de los tres casos, en formato ingestable
└── docs/lab-setup.md             Montaje reproducible de los tres laboratorios
```

Las consultas de [`queries/`](queries/) las extraje de los casos y las reescribí como
patrones aplicables a otros entornos: cómo construir una timeline de atacante en SPL,
cómo pivotar infraestructura con PassiveDNS en KQL, cómo distinguir un reverse shell de
tráfico legítimo en Wireshark.

Los [IOCs](iocs/iocs.csv) van en CSV con caso, tipo y contexto, listos para cargar en
un SIEM o una plataforma de threat intelligence.

## Sobre los datasets

Los tres escenarios son material de entrenamiento público y conocido. No son incidentes
propios ni datos reales de ninguna organización: son el banco de pruebas sobre el que
aplico el método. Lo que aporto aquí es la investigación: qué pregunto, en qué orden, y
qué concluyo de lo que no aparece en los logs.

## Más

Los writeups con todas las capturas están en
[mi Notion](https://jonathasapuntes.notion.site/Jonathas-Carneiro-Ciberseguridad-Defensiva-SOC-2de10ea9b490803d9cc3c49ec44924e3),
y el caso 01 lo explico en vídeo en [@DateUnH4ck](https://www.youtube.com/watch?v=mDertxflayg).

Proyecto relacionado: [elk-siem-lab](https://github.com/dat3unh4ck/elk-siem-lab), el
SIEM donde construyo las reglas que generan alertas como estas.

---

Jonathas Carneiro — Blue Team / SOC · [LinkedIn](https://www.linkedin.com/in/jonathascarneiro-soc/)
