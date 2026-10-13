# Consultas KQL — Azure Data Explorer

Las del [caso 03](../cases/03-jojos-hospital-ransomware.md). El esquema es el de KC7
(`Employees`, `FileCreationEvents`, `ProcessEvents`, `InboundNetworkEvents`,
`OutboundNetworkEvents`, `AuthenticationEvents`, `PassiveDns`), pero los patrones se
trasladan a Microsoft Sentinel cambiando los nombres de tabla y campo.

## Dimensionar un incidente de ransomware

Cuántos archivos se cifraron:

```kusto
FileCreationEvents
| where filename endswith ".encrypted"
| count
```

Sobre cuántas máquinas. Separar las dos preguntas importa: 6.420 archivos en 1 host y
en 321 hosts son incidentes distintos.

```kusto
FileCreationEvents
| where filename endswith ".encrypted"
| distinct hostname
```

## Localizar el origen

La nota de rescate suele estar en muchas máquinas, pero el punto de operación es
donde aparece primero o de forma aislada:

```kusto
FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
```

Identificar al propietario del host:

```kusto
Employees
| where hostname == "AMFB-MACHINE"
```

## Timeline de procesos

Toda la actividad de una máquina en la ventana del incidente. Ordenada, reconstruye el
ataque hora a hora:

```kusto
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
| order by timestamp asc
```

## Pivoteo de infraestructura con PassiveDNS

El patrón de dos pasos más rentable de la investigación. Primero, a qué IPs resuelve un
dominio malicioso:

```kusto
PassiveDns
| where domain == "secure-health-access.com"
```

Y después, qué otros dominios comparten esas IPs:

```kusto
PassiveDns
| where ip in ("203.0.113.1", "203.0.113.2")
```

Así es como `emr-help.net` apareció sin que nadie lo hubiera visto en los logs: un IOC
suelto se convierte en el mapa de la infraestructura del atacante.

## Reconocimiento previo

Tráfico entrante desde IPs ya identificadas. Suele revelar que el ataque empezó semanas
antes de lo que indica la alerta:

```kusto
InboundNetworkEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
| order by timestamp asc
```

## Autenticaciones sospechosas

```kusto
AuthenticationEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

Un `Successful Login` sin intentos fallidos previos apunta a credenciales ya conocidas
—robadas o compradas—, no a fuerza bruta.

## Caza de C2

Conexiones salientes a puertos inusuales. El 50050 es el puerto por defecto del team
server de Cobalt Strike:

```kusto
OutboundNetworkEvents
| where dest_port !in (80, 443, 53)
| summarize conexiones=count(), primera=min(timestamp), ultima=max(timestamp)
    by src_ip, dest_ip, dest_port
| order by conexiones desc
```

## Procesos dropeados por Office

Patrón de detección de maldocs: un proceso hijo de WINWORD, EXCEL o POWERPNT es casi
siempre malicioso.

```kusto
ProcessEvents
| where parent_process_name in~ ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE")
| where process_name !in~ ("splwow64.exe")
| project timestamp, hostname, parent_process_name, process_name, process_commandline
```

## Alcance de una campaña de phishing

Cuántas personas picaron y quién fue la primera:

```kusto
FileCreationEvents
| where filename contains "Raisin_Kane"
| summarize descargas=count(), primera=min(timestamp) by hostname
| order by primera asc
```
