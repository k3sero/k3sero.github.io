---
title: Invisible Ink - WarGamesCTF2024
author: Kesero
description: Reto de Miscelánea basado en la extración de información de un .gif.
date: 2024-12-30 15:15:00 +0800
categories: [Writeups Competiciones Internacionales, Pwn]
tags: [ gif, Fácil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/3.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `CryptoCat`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"The flag is hidden somewhere in this GIF. You can't see it? Must be written in transparent ink."

## Archivos

Este reto nos da los siguientes archivos.

- `challenge.gif` : Contiene el ejecutable a vulnerar.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink).

## Analizando el código

En este reto basicamente tenemos que extraer la información del gif aportado.


## Solución

En este caso teniamos que diseccionar el archivo.gif en todoas los frames con las imagenes a la que pertenecen, posteriormente habia 2 frames que contenia partes de un código QR, había que juntarlas y obteniamos el Qr completo. Posteriormente lo escaneábamos y era la flag.

```py
import numpy as np
import os
from PIL import Image  # Importar Image de Pillow

# Ruta del GIF con watermark
gif_path = "challenge.gif"

# Carpeta de salida para los fotogramas procesados
output_folder = "images/"

# Crear la carpeta si no existe
os.makedirs(output_folder, exist_ok=True)

# Paso 1: Extraer los fotogramas del GIF
frames = []  # Lista para almacenar los fotogramas como arrays
with Image.open(gif_path) as gif:
    frame_number = 0
    while True:
        # Guardar cada fotograma como PNG
        frame_path = os.path.join(output_folder, f"frame_{frame_number:03d}.png")
        gif.save(frame_path, "PNG")
        print(f"Guardado: {frame_path}")
        
        # Convertir el fotograma a formato RGB y guardarlo en la lista de fotogramas
        frames.append(np.array(gif.convert("RGB")))  # Convertir a formato RGB
        
        frame_number += 1
        try:
            gif.seek(frame_number)  # Avanza al siguiente fotograma
        except EOFError:
            break  # Salir del bucle al final de la animación
```



## Flag


`wgmy{6952956e2749f940428e6d16b169ac91}`