---
title: Mayday - Talent4Cyber2025
author: Kesero
description: Reto basado en recuperar un sistema de archivos UBI sobre UBIFS, analizar logs y descifrar una señal de radiofrecuencia 2-FSK
date: 2025-12-14 15:48:00 +0100
categories: [Writeups Competiciones Nacionales, Forense]
tags: [Forense, Forense - Recovery, Otros - Writeups, Dificultad - Media, Talent4Cyber]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/Talent4Cyber2025/Forense/Mayday/prompt.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Desconocido`

Dificultad: <font color=orange>Media</font>

## Enunciado

```
Nuestro equipo de fuerzas especiales recuperó un vehículo aéreo no tripulado tras su 
intercepción en una posición hostil; al volcar la memoria flash NAND del firmware se 
obtuvo una imagen UBI que contiene un sistema de archivos UBIFS (UBI sobre NAND cruda). 

Este hallazgo confirma la presencia de artefactos en la plataforma: registros de vuelo, 
configuraciones, logs de sensores y posibles capturas.

La información contenida en esa imagen adquiere especial valor para la monitorización de 
capacidades y la evaluación de riesgos. Tu misión es someter la imagen UBI a un análisis 
forense controlado para identificar y validar los artefactos de mayor relevancia; 
los resultados serán entregados al mando. 

Tu información ayudará a la protección de personal y activos.
```

## Archivos

- `drone_flash.bin`: Contiene los datos de la imagen UBI.

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Nacionales_Writeups/2025/Talent4Cyber2025/Forense/Mayday).

## Analizando el reto

Mediante el programa `file`, se descubre una imagen UBI que contiene un sistema de archivos UBIFS (UBI sobre NAND cruda)

```
┌──(kesero㉿kali)-[~]
└─$ file drone_flash.bin

    drone_flash.bin: UBI image, version 1
```

Para obtener el sistema de archivos de una imagen `UBI`, se utilizarán herramientas forenses para manipular la información dentro de sistemas `UBIFS`. En este caso, se utiliza `ubi_reader` para realizar el volcado del sistema de archivos.

```
┌──(kesero㉿kali)-[~]
└─$ pip install ubi_reader  
```

```
┌──(kesero㉿kali)-[~]
└─$ ubireader_extract_files drone_flash.bin

    Extracting files to: ubifs-root/1812447777/telemetry
    Extracting files to: ubifs-root/1812447777/missions
    Extracting files to: ubifs-root/1812447777/secure
    Extracting files to: ubifs-root/1812447777/cfg
```

El sistema de archivos extraído es el siguiente:

```
|-- cfg
|   |-- device.conf
|   |-- flight.conf
|-- missions
|   |-- obj_1.png
|   |-- obj_3.png
|   |-- per.png
|   |-- Recon.pdf
|-- secure
|   |-- img_files
|   |   |-- 2025-09-13T13:18:20.png
|   |   |-- 2025-09-13T13:18:21.png
|   |   |-- (...)
|   |
|   |-- sender
|   |-- sender_file
|       |-- 2025-09-13T13:18:31.iq
|-- telemetry
    |-- telemetry.log
```

En el directorio `cfg` se encuentra la configuración principal del dron junto con los parámetros iniciales de vuelo.

En la carpeta `missions` se encuentra información clasificada sobre la misión a la que pertenece el dron capturado. En esta sección, se obtiene información relevante como el cometido principal de la misión, así como unas imágenes del objetivo.

![ob_2](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/Talent4Cyber2025/Forense/Mayday/img/obj_2.png)

En dicha información clasificada, se menciona la necesidad de realizar pruebas exhaustivas en mantenimiento preventivo para evitar fallos técnicos.

En la carpeta `telemetry` se obtiene un archivo de log sobre los datos de telemetría de vuelo del dron.

Al analizar el archivo `telemetry.log`, se obtienen registros periódicos sobre la comunicación entre el dron y la base, junto con el envío de la información e imágenes tomadas en ese instante.

Además, se obtiene el fallo principal ocasionado por el mal funcionamiento de los servomotores, los cuales comienzan a fallar progresivamente junto a la comunicación con la base.

Una vez la comunicación con la base no resulta exitosa, el dron almacena tanto las imágenes capturadas, como la última señal `sender` de comunicación en la carpeta `secure` hasta que, finalmente, el dron deja de guardar registros de su telemetría por fallo crítico en su sistema interno.

Por último, en la carpeta `secure` se obtienen las últimas imágenes capturadas por el dron junto al binario `sender`, que codifica información en formato de señal, así como la última señal codificada.

![1](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/Talent4Cyber2025/Forense/Mayday/img/2025-09-13T13_18_30.png)
![2](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/Talent4Cyber2025/Forense/Mayday/img/2025-09-13T13_18_32.png)

El archivo `sender` codifica un mensaje de texto introducido en una señal digital modulada en 2-FSK (Frequency Shift Keying). Cada carácter se transforma en 8 bits, y cada bit se codifica como una onda sinusoidal a 100kHz para bit 0 y 110kHz para bit 1 con una frecuencia de muestreo de 1MHz.

Finalmente la señal resultante se almacena como pares de valores flotantes I y Q en un archivo con nombre basado en la fecha y hora actual.

Se decodifica la señal `2025-09-13T13:18:31.iq` mediante análisis estático del binario `sender` con herramientas como `ghidra`, obteniendo el tipo de modulación y sus parámetros utilizados. Se revierte el código de codificación para extraer la información de la señal obtenida.

El siguiente código realiza la operación de decodificación:

```py
import numpy as np

fs = 1_000_000
baud = 1000
samples_per_symbol = fs // baud

iq = np.fromfile("2025-09-13T13:18:31.iq", dtype=np.float32)
iq = iq[::2] + 1j*iq[1::2]

inst_phase = np.angle(iq[1:] * np.conj(iq[:-1]))
freq_inst = np.unwrap(inst_phase) * fs / (2*np.pi)

bits = []
for i in range(0, len(freq_inst), samples_per_symbol):
    f = np.mean(freq_inst[i:i+samples_per_symbol])
    bits.append(1 if f > 105e3 else 0)

bit_str = ''.join(map(str, bits))
msg = ''.join(chr(int(bit_str[i:i+8], 2)) for i in range(0, len(bit_str), 8))
print(msg)
```

## Flag

`t4c2025{H0ustOn_t3n3M0s_Un_Pr0bl3M4!!!}`