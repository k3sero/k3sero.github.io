---
title: GeoGuessitFVG - SnakeCTF2025 Final
author: Kesero
description: Reto basado en geolocalizar una carretera con un poste de luz en la región de FVG
date: 2025-12-09 17:00:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Osint, Osint - Geo, Otros - Writeups, Dificultad - Fácil, SnakeCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitFVG/13.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Desconocido`

Dificultad: <font color=green>Fácil</font>

## Enunciado

```
"Geoguess it. It's easy. It's in the FVG special administrative region.

Our friend got lost while driving back home with his snake friends. He recorded this video and then stopped the car shortly after ending the recording. Can you help us locate him now?"
```

## Archivos

En este reto tenemos el siguiente archivo:

- `geoguessitFVG.mp4`: Contiene un vídeo del lugar.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitFVG).


## Analizando el reto

En el vídeo proporcionado, se observa cómo el conductor circula por una carretera rural, rodeada de maizales, con montañas visibles a lo lejos.

Hay dos elementos especialmente distintivos:

1. Los postes de alta tensión

![poste](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitFVG/post.png)

Los postes que aparecen en el vídeo son característicos de Italia.
El diseño coincide con los típicos elettrodotti aerei de media/alta tensión utilizados en Friuli-Venezia Giulia.
Consultando documentación oficial sobre líneas eléctricas en la región, encontramos exactamente el mismo tipo de infraestructuras.

De hecho, los postes eléctricos del lugar están registrados y mapeados independientemente de su tamaño y capacidad voltaica en la [página oficial de arpa](https://www.arpa.fvg.it/temi/temi/campi-elettromagnetici/sezioni-principali/linee-elettriche/#open-modal-elettrodotti).

![arpa_page](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitFVG/page.png)

2. La señalización de carretera

![road](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitFVG/road.png)

Los delineadores laterales son los típicos reflectores blancos con rectángulo rojo, estándar en carreteras secundarias italianas.
La carretera además es demasiado estrecha para ser una SP principal, lo que sugiere que dicha carretera es un camino agrícola o una carretera comunal.

## Solver

Si se observa el vídeo, se encuentran dos líneas eléctricas de alto voltaje que cruzan la carretera por la cual el conductor circula. Gracias a este detalle, podemos filtrar en el mapa interactivo por líneas eléctricas paralelas de gran voltaje que cruzan una carretera las cuales cuentan con torres eléctricas de gran tamaño. Además, se sabe que los campos de alrededor pertenecen a maizales de gran tamaño, por lo que las zonas colindantes forman parte de zonas agrícolas de gran tamaño.

Filtrando por la zona de FVG, se encuentra el lugar mencionado.

![find](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitFVG/find.png)

![flag](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitFVG/final.png)


## Flag
`snakeCTF{Ov3r_9000_v0lts_71b0b94bcb1b03bf}`