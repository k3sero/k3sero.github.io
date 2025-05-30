---
title: Signals - Hardware HackThebox
author: Kesero
description: Reto basado en decodificar una señal SSTV proveniente del espacio.
date: 2025-05-30 9:00:00 +0000
categories: [Hack The Box, Hardware - HTB]
tags: [Writeups, Dificultad - Fácil, Hardware, Hardware - Signal, HTB, HTB - Hardware]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/assets/Hardware.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `brigante`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"Some amateur radio hackers captured a strange signal from space. A first analysis indicates similarities with signals transmitted by the ISS. Can you decode the signal and get the information?"

## Archivos

En este reto, tenemos el siguiente archivo.

- `signal.wav`: Contiene un audio de la señal capturada.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/HackTheBox/Hardware/Signals).

## Analizando el reto

Lo primero de todo como siempre es lanzarle un `file` al archivo para ver de qué se trata.

```
    ┌──(kesero㉿kali)-[~]
    └─$ file Signal.wav

    Signal.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 48000 Hz
```

Dado el contexto del reto, este archivo contiene datos codificados por radio. Si escuchamos el audio en si, podemos observar que cuenta con numerosos pitidos que se repiten durante la duración del mismo.

## Solver

Este tipo de señal debe de estar codificada en algún tipo de codificación por radio. Las más conocidas que se pueden asociar a este caso en particular pueden ser las siguientes.

```
AX.25 (APRS, packet radio)
RTTY (Radioteletype)
SSTV (Slow Scan TV)
Morse (CW)
FSK (Frequency Shift Keying)
AFSK (como usado en APRS)
```

Si tomamos archivos de audios generados por cada uno de estos tipos de codificación, podemos observar como hay una gran similitud entre el audio original `signal.wav` y la codificación mediante `SSTV (Slow Scan TV)`.

SSTV (Slow Scan Television) es un método para transmitir imágenes estáticas (generalmente en color) por radio de onda corta o VHF/UHF, en este caso la ISS (Estación Espacial Internacional) también utiliza este tipo de codificación, por lo que intuimos que vamos por buen camino.

Este tipo de método, transmite imágenes codificadas en audio, generalmente entre 1100 y 2300 Hz. Además utiliza modulación FM o SSB para transmitir vía radio. Dicha imagen se transmite línea por línea como tonos de frecuencia variable.

Si nos adentramos en su funcionamiento, cada línea horizontal de la imagen se codifica como una variación de frecuencia (parecido a un fax). Además, las frecuencias típicas más utilizas son para el blanco = ~2300 Hz, para el negro = ~1500 Hz y para la sincronización de pulsos = ~1200 Hz

Una vez visto de manera teórica cómo funciona dicha codificación, utilizaremos el programa `Qsstv` para operar con este tipo de señales, para ello nos descargaremos la herramienta desde su [Página Oficial](https://www.qsl.net/o/on4qz//qsstv/downloads/)

Además, para instalar la herramienta, deberemos de seguir el manual de [instalación oficial](https://www.qsl.net/on4qz/qsstv/manual/installation.html) de la propio página qsl.

Una vez instalado, nos iremos a `Options > Configuration` y en el apartado de `Sound`, cargaremos el archivo `signal.wav`.

Una vez hecho, le daremos al botón de `Play` para reproducir la secuencia y obtener la imagen codificada.

![imga](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Signals/flag.jpg)

## Flag
`HTB{5l0w-5c4n_73l3v1510n_h4m_r4d10_h4ck3r}`
