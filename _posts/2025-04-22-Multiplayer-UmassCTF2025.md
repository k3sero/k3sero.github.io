---
title: Multiplayer - UmassCTF2025
author: Kesero
description: Reto basado en encontrar un punto medio en base a 2 coordenadas.
date: 2025-04-14 12:30:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Fácil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Multiplayer/1.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Posco`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"You and a friend want to play Fireboy and Watergirl in the Forest Temple, but you both live quite far away. You both want to meet up roughly halfway by distance, you want to meet at a place that has public computers, and you want to meet up at a place that shares the name of the street where you both live. What’s the address of where that could be?

Flag format: UMASS{Address as on Google Maps}, e.g. UMASS{650 N Pleasant St, Amherst, MA 01003} for the Integrative Learning Center at UMass."

## Archivos

Este reto nos da el siguiente archivo.

- `Multiplayer 1` : Contiene la 1º localización
- `Multiplayer 2` : Contiene la 2º localización

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Multiplayer).

![Mul1](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Multiplayer/img/multiplayer1.jpeg?raw=true)
![Mul2](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Multiplayer/img/multiplayer2.jpeg?raw=true)

## Analizando el reto

En este reto tenemos que encontrar la ubicación donde se reunirán a jugar a un juego.
La información que nos aporta el enunciado es la siguiente.

```
La ubicación tiene ordenadores públicos y se encuentra en el punto medio
El nombre del lugar comparte el nombre de la calle donde viven.
```

## Solver.py

Primero que todo, tenemos que encontrar los lugares pertenecientes a ambas imágenes. Para ello utilizaremos las herramientas mencionadas [aquí](https://k3sero.github.io/posts/Gunnar-Vacations-THCON2025/) para encontrar realizar Geolocalizar los lugares.

Para la imagen `multiplayer1` podemos encontar que su ubicación es ["19th at Pennsylvania SB"](https://www.google.com/maps/@40.6130276,-75.5048425,3a,81.2y,41.12h,83.17t/data=!3m7!1e1!3m5!1sUlfcq5EKgG2V9LRTbLxfnQ!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D6.829999999999998%26panoid%3DUlfcq5EKgG2V9LRTbLxfnQ%26yaw%3D41.12!7i16384!8i8192?authuser=0&hl=es&entry=ttu&g_ep=EgoyMDI1MDQyMC4wIKXMDSoASAFQAw%3D%3D)

![ubi1](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Multiplayer/img/ubi1.png?raw=true)

Para la imagen `multiplayer2` podemos encontar que su ubicación es ["Pennsylvania Ave & Norfolk St"](https://www.google.com/maps/@37.6496951,-77.4639334,3a,75y,352.11h,86.41t/data=!3m7!1e1!3m5!1slmKLvrETVqPuVByjzdpsBw!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D3.5900000000000034%26panoid%3DlmKLvrETVqPuVByjzdpsBw%26yaw%3D352.11!7i16384!8i8192?hl=es&entry=ttu&g_ep=EgoyMDI1MDQyMC4wIKXMDSoASAFQAw%3D%3D)

![ubi2](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Multiplayer/img/ubi2.png?raw=true)

Si ponemos los puntos en un mapa, veremos lo siguiente.

![mid](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Multiplayer/img/ubi_media.png?raw=true)

Como en el enunciado del reto nos dicen que la ubiación se encuentra en el punto medio de ambos, sabemos que la ubiación que nos piden debe de estar en `Baltimore`. Además si miramos sus direcciones, llegamos a la conclusión de que sus calles se llaman igual "Pennsylvania Ave Street" por lo que sabemos que el lugar va a contener la palabra `Pennsylvania`

Buscando por Baltimore, finalmente encontramos la ubiación, [""]()

![ubi_final](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Multiplayer/img/ubi_final.png?raw=true)


## Flag

`UMASS{39.310,-76.642}`

## PD

Créditos a [sumurazmirzayev](https://medium.com/@sumurazmirzayev/multiplayer-umassctf-2025-osint-3638afb867f8)

Mirando soluciones he visto una técnica muy buena. Normalmente hay imágenes que suelen tener en metadatos su la ubicación de donde se tomaron, para ello es muy recomendable siempre utilizar `exiftool` para intentar extraer esa información.

En este caso, estas imágenes pertenecen a "Street View Download 360" y por tanto tienen un identificador único llamado "Panorama ID" el cual identifica la ubicación exacta.

![id1](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*tldE0krcUZbDdjED_UVvNg.png)

![id2](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*JRDrKniQweKuSk4IeGjiGg.png)

Una vez obtenido su identificador, nos vamos a la aplicación "Street View Download 360" y buscamos esos identificadores.

![ids](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*_UgaTf85IT1kn6-Ag5Y7og.png)
![ids2](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*E2isPK3Gvl2ICTq7RhRzNg.png)

Por último obtenemos sus coordenadas.

![coords](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*4e5Ba04i8iTDiGoUEEgGDA.png)