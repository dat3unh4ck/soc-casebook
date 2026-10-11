# Consultas SPL — Splunk

Las del [caso 01](../cases/01-wayne-enterprises-web-compromise.md), reescritas como
patrones reutilizables. Sustituye `index=botsv1` por tu índice.

## Reconocimiento del entorno

Qué fuentes de datos hay y cuánto aporta cada una. Primera consulta ante un índice
desconocido: dice qué visibilidad tienes realmente.

```spl
index=botsv1 earliest=0
| stats count by sourcetype | sort -count
```

## Alertas IDS

Firmas activadas, ordenadas por volumen:

```spl
index=botsv1 earliest=0 sourcetype=suricata alert.signature=*
| stats count by alert.signature | sort -count
```

Quién habla con quién en una firma concreta:

```spl
index=botsv1 earliest=0 sourcetype=suricata "Acunetix"
| stats count by src_ip dest_ip
```

## Timeline de un atacante

Patrón clave de triaje: primera y última aparición de cada firma para una IP. Revela
la secuencia del ataque y su duración.

```spl
index=botsv1 earliest=0 sourcetype=suricata src_ip="40.80.148.42"
| stats min(_time) as inicio max(_time) as fin count by alert.signature
| eval inicio=strftime(inicio,"%Y-%m-%d %H:%M:%S")
| eval fin=strftime(fin,"%Y-%m-%d %H:%M:%S")
| sort inicio
```

## Análisis de servidor web (IIS)

Rutas más golpeadas por una IP — delata el objetivo real:

```spl
index=botsv1 earliest=0 sourcetype=iis c_ip="40.80.148.42"
| stats count by cs_uri_stem | sort -count | head 20
```

Distribución de códigos de respuesta. Muchos 500 indican explotación activa; los 200
en rutas sensibles indican éxito:

```spl
index=botsv1 earliest=0 sourcetype=iis c_ip="40.80.148.42"
| stats count by sc_status | sort -count
```

Detección de login exitoso por método y código, aplicado a un panel de administración:

```spl
index=botsv1 earliest=0 sourcetype=iis c_ip="40.80.148.42"
  cs_uri_stem="/joomla/administrator/index.php"
| stats count by cs_method sc_status | sort -count
```

> Un `POST` con `303` en Joomla es una redirección post-autenticación: login correcto.
> El código de estado concreto depende de la aplicación — conviene verificarlo antes
> de dar por buena la conclusión.

## Fuerza bruta sobre formularios web

Intentos de login capturados en el tráfico HTTP. Útil cuando la aplicación no registra
los fallos en sus propios logs:

```spl
index=botsv1 earliest=0 sourcetype=stream:http dest_ip="192.168.250.70"
  http_method=POST form_data=*username*passwd*
| stats count by src_ip
```

## Detección de web shell

Un web shell suele ser una ruta poco frecuente con muchísimos accesos de una sola IP y
sin query string. Este patrón lo saca a la luz:

```spl
index=botsv1 earliest=0 sourcetype=iis
| stats count dc(c_ip) as ips_distintas by cs_uri_stem
| where count > 50 AND ips_distintas <= 2
| sort -count
```

## Verificación del IPS

La consulta que destapó el caso 01: comprobar qué proporción de lo detectado se está
**permitiendo** de verdad.

```spl
index=botsv1 earliest=0 sourcetype=fortigate_utm
| stats count by action
```

Si `allowed` domina sobre `blocked`, el IPS está en modo detección y la defensa es
decorativa.
