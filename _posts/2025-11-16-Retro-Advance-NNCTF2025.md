---
title: Retro Advance - NNCTF2025
author: Kesero
description: Reto basado en la transmisión de una ROM de GBA a través de ondas de radio siguiendo el estándar FSK Bell 202.
date: 2025-11-16 18:10:00 +0000
categories: [Writeups Competiciones Nacionales, Hardware N]
tags: [Hardware, Hardware - Radiofrecuencia, Otros - Writeups, Dificultad - Fácil, NNCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/NNCTF2025/hardware_rf/Retro_Advance/8.png
  lqip: 
  alt: 
comments: true
---

Nombre del reto: `Retro Advance`

Autor del reto: `Kesero` (Creado por mí)

Dificultad: <font color=green>Fácil</font>

## Enunciado
    
    El pasado fin de semana estuve con mi tío revisando algunos de sus viejos recuerdos. Entre anécdotas y risas, me contó algo que me dejó sin palabras. En su época, algunos videojuegos se distribuían por radio o venían escondidos en paquetes de cereales. Pensé que me estaba tomando el pelo, hasta que me enseñó un par de antiguos casetes que tenía guardados.

    Resulta que mi tío había capturado una transmisión hace años: una ROM de Game Boy Advance emitida por la radio. Nunca supo cómo decodificarla, pero guardó la grabación "por si acaso".

    Como sabe que me interesan estas cosas, me la pasó y me dijo: "A ver si tú puedes hacer algo con esto."
    La verdad... yo no tengo ni idea de por dónde empezar.

    ¿Te animas a echarme una mano y ver si hay algo jugable en esa señal?


## Archivos

    sound.wav

## Analizando el reto

Al abrir el archivo `sound.wav` con programas de audio como `Audacity` se encuentra lo siguiente:

![audacity](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/NNCTF2025/hardware_rf/Retro_Advance/solver/images/audacity.png)

Este tipo de señal tan característica de dos frecuencias bien definidas, corresponde a una codificación por FSK en la que cada periodo transmite un bit de información.

## Solución

### Decodificación de la señal

Siguiendo la historia del enunciado, antiguamente había canales de radio que transmitían videojuegos (ZX Spectrum, Commodore 64, etc.) en formato de audio, en el que los oyentes grababan en cinta. En aquella época, uno de los esquemas más conocidos y utilizados fue el estándar `Bell 202`, que transmitía `1200 baudios` con frecuencias de `1200 Hz` que simbolizaban el bit `1` y frecuencias de `2200 Hz` que representaban el bit `0`.

Siguiendo la analogía histórica, el archivo proporcionado `sound.wav` se corresponde con una señal FSK codificada siguiendo el estándar `Bell 202` descrito anteriormente.

Teniendo esta información en cuenta, podemos interpretar la señal en `Audacity` de la siguiente manera:

![bits](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/NNCTF2025/hardware_rf/Retro_Advance/solver/images/bits.png)

Para completar la decodificación del audio, podemos utilizar scripts automatizados en Python o directamente emplear la herramienta `minimodem`, la cual nos permitirá convertir entre datos digitales y señales de audio moduladas.

Para instalarlo utilizamos:

```
[~]─$ sudo apt install minimodem
```

Decodificamos la señal de la siguiente manera:

```
[~]─$ minimodem --rx 1200 --mark 1200 --space 2200 -f sound.wav > recovered

    ### CARRIER 1200 @ 1200.0 Hz ###

    ### NOCARRIER ndata=1188828 confidence=4.575 ampl=1.000 bps=1200.00 (rate perfect) ###
```

Para asegurarnos de que la decodificación fue exitosa, comprobamos sus metadatos:

```
[~]─$ file recovered

    recovered: Game Boy Advance ROM image: "MIGUELITOS" (SBTP01, Rev.00)
```

### Abrir la ROM

Una vez contamos con la ROM original del videojuego, utilizaremos el emulador gratuito [mgba](https://mgba.io/) para cargar juegos de Gameboy Advance. Al cargar la ROM, nos daremos cuenta de que el videojuego se basa en un "Catch game" en el que para obtener la flag, tendremos que capturar 40 Miguelitos sin ser abatidos en el intento, esquivando los cuchillos y tomando jarras de cerveza para obtener vidas extra.

![rom](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/NNCTF2025/hardware_rf/Retro_Advance/solver/images/rom.png)
![resolucion](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/NNCTF2025/hardware_rf/Retro_Advance/solver/images/resolucion.png)
![juego](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/NNCTF2025/hardware_rf/Retro_Advance/solver/images/juego.png)
![flag](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/NNCTF2025/hardware_rf/Retro_Advance/solver/images/flag.png)

## Flag

`nnctf{V13j4s_EpOcAs_Tr4en_Vi3j0s_r3cuErdOs!!!}`