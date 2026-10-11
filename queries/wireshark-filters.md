# Filtros de Wireshark

Los del [caso 02](../cases/02-apache-tomcat-takeover.md), con el razonamiento detrás de
cada uno. Son filtros de visualización, no de captura.

## Detectar un escaneo de puertos

SYN sin ACK desde una IP: peticiones de conexión que no son respuestas. Un volumen alto
es un escaneo.

```
ip.src == 14.0.0.120 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

El filtro inverso es el que de verdad importa: SYN-ACK **desde el servidor** son los
puertos que respondieron, es decir, lo que el atacante descubrió.

```
ip.src == 10.0.0.112 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

## Peticiones HTTP de una IP

```
ip.src == 14.0.0.120 && http.request.method == "GET"
```

Compara siempre el **User-Agent** entre peticiones: el salto de un navegador real a
`gobuster/3.6`, `nikto` o `curl` marca dónde empieza la fase automatizada. Y el salto
de vuelta marca dónde interviene un operador humano.

```
http.user_agent contains "gobuster" || http.user_agent contains "nikto"
```

## Buscar un panel de administración

```
ip.src == 14.0.0.120 && http.request.uri contains "manager"
```

## Autenticación HTTP Basic

El filtro más rentable de un PCAP con tráfico HTTP sin cifrar:

```
http.authorization
```

HTTP Basic transmite las credenciales en **Base64, que no es cifrado**. Wireshark
muestra la cabecera; decodificarla da el usuario y la contraseña en claro:

```
Authorization: Basic YWRtaW46dG9tY2F0   →   admin:tomcat
```

Si hay varios intentos seguidos y luego peticiones normales con la misma cabecera, ahí
está el punto exacto donde la fuerza bruta tuvo éxito.

## Subida de ficheros

```
http.request.method == "POST" && http.content_type contains "multipart/form-data"
```

En el detalle del paquete, `Content-Disposition` da el nombre del fichero subido.

## Tráfico posterior a un evento concreto

Una vez identificado el paquete del compromiso, aislar lo que vino después:

```
ip.addr == 14.0.0.120 && tcp && frame.number > 20616 && !http
```

El `!http` es deliberado: deja fuera el ruido web para que se vea el canal C2.

## Identificar un reverse shell

```
ip.src == 10.0.0.112 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Mismo filtro que el escaneo, pero aplicado **al servidor**. Un servidor que inicia
conexiones salientes hacia una IP externa es la firma de un reverse shell: el sentido
natural está invertido.

Para leer los comandos: clic derecho sobre el paquete → **Follow → TCP Stream**.

## Reconocimiento inicial de cualquier PCAP

Antes de filtrar nada, tres menús en este orden:

| Menú | Qué responde |
|---|---|
| **Statistics → Protocol Hierarchy** | Qué hay en la captura. Mucho TCP sin capa de aplicación = escaneo |
| **Statistics → Conversations** | Quién habla con quién y cuánto. Identifica a los actores |
| **Statistics → Endpoints** | Qué puertos y servicios están activos |

En el caso 02, estos tres menús bastaron para pasar de 21.070 paquetes a dos IPs y un
puerto, antes de escribir un solo filtro.
