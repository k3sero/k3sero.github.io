---
title: More Sleuth - DAMCTF2025
author: Kesero
description: Reto basado en encontrar el avión fantasma dentro de un reporte de radio mediante una captura en ADS-B.
date: 2025-05-11 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Otros - Writeups, Dificultad - Media, Osint, Osint - Research, DAMCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Misc/Mode%20Sleuth/img/3.png
  lqip: 
  alt: 
comments: true
---
Autores del reto: `KeKoa_M, alienfoetus`

Dificultad: <font color=orange>Media</font>

## Enunciado

"Software defined radio is so fun! I just recorded a bunch of planes near me, but I think someone messed with the data. Can you find the plane that is not supposed to be there?

Flag format: dam{<N-number>_<Registered owner name>_<serial number>}

Note: must be all caps, owner name should be full name including any spaces Example: dam{N249BA_BOEING AIRCRAFT HOLDING CO_24309}"

## Archivos

En este reto, tenemos el siguiente archivo.

- `captura.txt`: Contiene la captura de radio de los logs de aviones.

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Misc/Mode%20Sleuth).


## Analizando el reto

En la `captura.txt` podemos encontrar la siguiente información.

```
*8DA37DB958BF0299ECD4CFB09C63;
*8DA37DB99911BD8DD80414F5B235;
*02E197B0E91C84;
*5DAB8D760E80DC;
*02E19338DEACE7;
*8DAB8D76589B82A3FD2E748E7900;
*8DAB8D769915579790040EA86431;
*8DAB8D76EA3AB860015F48BFFCAD;
*20001338D874AD;
*02E19338DEACE7;
*5DAB8D760E80DF;
*02E61338069104;
*02E19338DEACE7;
*8DAB8D76589B86322DA4C2393F69;
*8DAB8D769915579790080EE03E31;
*5DAB8D760E80DC;
*8DAB8D76589B86320DA4A781CDAF;
*02E19338DEACE7;
*8DAB8D76EA3AB860015F48BFFCAD;
*8DAB8D76589B82A3932E1601F83E;
*8DAB8D769915579790080F1FCA38;

(...)
```

Este reporte, coincide con una captura `ADS-B`. Una captura ADS-B (Automatic Dependent Surveillance–Broadcast) se refiere a la recolección de señales transmitidas por aviones que usan el sistema ADS-B para enviar información sobre su posición, velocidad, altitud, identificación, y más.

Básicamente podemeos decir que es un sistema de vigilancia usado en aviación que permite a las aeronaves determinar su propia posición mediante GPS, transmitir esa posición y otros datos automáticamente y de forma continua a estaciones de tierra y otras aeronaves cercanas.

El tipo de información que se transmite en estas señales suele incluir el identificador de la aeronave, (número de vuelo), posición (latitud y longitud), velocidad, rumbo, estado del transpondedor y a veces información del plan de vuelo.

## Solver

Para resolver este reto, primero tenemos que comprender la información que tenemos en `captura.txt`

Por ejemplo, hay líneas en nuestro documento que transmiten un mensaje `Mode S extendido` y otras en formato `Mode S short`, ambas se encuentran en formato hexadecimal y sólo se diferencian en longitud.

Estas tramas suelen comenzar con `*` seguida de 28 caracteres hexadecimales (14 bytes) y terminan en `;`.

Para ponernos en situación, un mensaje de 112 bits (14 bytes) contiene la siguiente información.

1. Formato / tipo de mensaje (5 bits).

2. ICAO address (24 bits) – identificación única del avión.

3. Payload (datos variables) – pueden ser posición, altitud, velocidad, identificación, etc.

4. CRC (24 bits) – para comprobar errores.

Si ponemos de ejemplo el mensaje `*8DAB8D76589B82A3FD2E748E7900;`, podemos desglosar la siguiente información.

1. 8D equivale al tipo de mensaje y transpondedor:

2. 8D indica un mensaje ADS-B tipo 17 (Downlink Format 17), lo que significa que contiene datos útiles como posición, identificación o velocidad.

3. AB8D76 → ICAO address de la aeronave (hexadecimal). Esta dirección, identifica de forma única al avión. Puede buscarse en bases de datos como ADSBExchange o OpenSky Network.

4. El resto 589B82A3FD2E748E7900 → Es el contenido y CRC, y requiere decodificación binaria para entender si es un mensaje de posición, velocidad, o identificación.

Otro ejemplo son los mensajes que no comienzan por `8D` como por ejemplo `*20001338D874AD;`, los cuales se desglosan de la siguiente manera.

1. 20 equivale a Downlink Format 4, posiblemente una respuesta de interrogación del radar secundario (SSR). No es un mensaje ADS-B completo, pero puede contener datos útiles como Squawk code o identificadores.

2. 5DAB8D76... también es un mensaje válido, de otro tipo, probablemente un DF11 o DF5 (respuestas sin ADS-B, transpondedor puro).

Para que no tengamos dudas, podemos listar toda la información utilizando el módulo `pyModeS` de python para llevar a cabo la automatización de la información.

Con el siguiente script, podremos listar toda la información perteneciente a cada registro.

```py
import pyModeS as pms

# Archivo de entrada y salida
archivo_entrada = "captura.txt"
archivo_salida = "resultado_adsb.txt"

def procesar_mensaje(msg):
    msg = msg.strip().strip('*').strip(';')
    
    if len(msg) != 28 or not msg.startswith("8D"):
        return None  # No es un mensaje ADS-B de 112 bits

    icao = pms.adsb.icao(msg)
    tc = pms.adsb.typecode(msg)

    resultado = {
        "raw": msg,
        "icao": icao,
        "typecode": tc,
    }

    if 1 <= tc <= 4:
        resultado["tipo"] = "Identificación"
        resultado["callsign"] = pms.adsb.callsign(msg)

    elif 9 <= tc <= 18:
        resultado["tipo"] = "Posición (Airborne)"
        resultado["altitud"] = pms.adsb.altitude(msg)
        resultado["lat/lon"] = "Codificado (CPR, requiere más de 1 msg)"

    elif tc == 19:
        resultado["tipo"] = "Velocidad"
        vs = pms.adsb.velocity(msg)
        if vs:
            resultado["velocidad"] = f"{vs[0]} knots"
            resultado["rumbo"] = f"{vs[1]}°"
            resultado["ascenso/descenso"] = f"{vs[2]} ft/min"

    else:
        resultado["tipo"] = "Otro"

    return resultado

def main():
    resultados = []

    with open(archivo_entrada, "r") as f:
        lineas = f.readlines()

    for linea in lineas:
        datos = procesar_mensaje(linea)
        if datos:
            resultados.append(datos)

    # Escribir en archivo
    with open(archivo_salida, "w") as out:
        for datos in resultados:
            out.write("-" * 40 + "\n")
            for k, v in datos.items():
                out.write(f"{k}: {v}\n")

    print(f"\n Resultados guardados en '{archivo_salida}'")

if __name__ == "__main__":
    main()

```

Con la información listada y desgranada, tendremos que revisar los datos publicos de aviación para determinar que aviones destacan o probablemente no estarían en la zona en la que se produce el resto de captura. Es por ello que investigando a fondo la procedencia de cada uno de los aviones, finalmente encontrábamos que un avión con el `ICAO:` `ADF94B` perteneciente al mensaje `*8DAD0887590F563867B7CADF94B1;` el cual se corresponde con el avión `NASA Shuttle Carrier aircraft` con la dirección en la cola de `905NA`.

Este avión se corresponde al legendario Shuttle Carrier Aircraft (SCA) de la NASA, un Boeing 747 modificado para transportar el transbordador espacial y fue el encargado de trasladar el transbordador espacial Shuttle entre bases. Por ello, en el contexto del problema no encaja.

A partir de este momento, tenemos que encontrar reportes públicos con más información sobre la nave. Para ello utilizaremos páginas como [gis.icao](https://gis.icao.int/portal/home/item.html?id=14a985339f224d23af60ce8f37f8cd09) o como [hexdb](https://hexdb.io/#api-body) los cuales permiten la identificación de aviones en base al `ICAO` y otros parámetros en cuestión.

Afinando la búsqueda, encontramos `serial number` el cual se corresponde con `20107` y finalmente el nombre de registro `NATIONAL AERONAUTICS AND SPACE ADMINISTRATION`

## Flag
`dam{N905NA_NATIONAL AERONAUTICS AND SPACE ADMINISTRATION_20107}`