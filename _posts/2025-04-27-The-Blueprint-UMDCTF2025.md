---
title: The Blueprint - UMDCTF2025
author: Kesero
description: Reto basado en Geolocalizar una ubicación en base a una colina en Ohio.
date: 2025-04-27 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Osint]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/prompt.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Segal`

Dificultad: <font color=orange>Medio</font>

## Enunciado

"always respect the blueprint (she's never coming back lil bro (i am heartbroken)). anyways, what street are we on?

flag will look like: UMDCTF{Campus Dr, College Park, MD 20742}"

## Archivos

Este reto nos da el siguiente archivo.

- `the-blueprint.jpg` : Contiene la imágen 360º del reto en formato .jpg

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img).

![blueprint](https://raw.githubusercontent.com/k3sero/Blog_Content/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/the-blueprint.jpg)

## Analizando el reto

En la imagen proporcionada podemos distinguir que se trata de una zona residencial en Ohio la cual presenta elementos verdes provenientes de las zonas alejadas a los suburbios urbanos y además podemos intuir que se trata de una zona lujosa, debido a la arquitectura de las casas de alrededor.

Los elementos de la imagen que más llaman la atención es la siguiente.

![valla](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/signal.png)

![casa](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/casa.png)

Además como esta imagen se corresponde a una imagen tomada en Google Maps y además nos dan la imagen panorámica, con visualizadores como [Renderstuff](https://renderstuff.com/tools/360-panorama-web-viewer/) podemos visualizarla de forma completa. De este modo entenderemos al 100% la morfología urbana del lugar.

## Solver

Para resolver este reto podemos realizarlo de dos maneras, con un script en `Overpass-Turbo` que filtre por calles cortadas o mediante métodos manuales.

### Script en Overpass-Turbo

El siguiente script busca por calles cortadas alrededor de todo Ohio.

```py
[out:json][timeout:90];

// Área de búsqueda: Ohio
{{geocodeArea:Ohio}}->.searchArea;

// --- Parte 1: rotondas ---
(
  way["junction"="roundabout"](area.searchArea);
  // 2.2 Señales explícitas de cierre de calle
  node["traffic_sign"="road_closed"](area.searchArea);
);

// Mostrar resultados
out body;
>;
out skel qt;
```

Después de ejecutar el script, nos aparecerán unas 6290 ocurrencias. El problema es que de este método tendremos que ir filtrado por las que a simple vista no sean coincidentes con el lugar, pero poco a poco tenemos la certeza de que nuestro punto en el mapa se corresponde a uno de ellos.

![ubi_overpass](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/overpass_turbo_photo.png)

Para ir descartando nodos, podemos exportar el resultado en formato geojson e importarlo con la herramienta web [Geojson.io](https://geojson.io/#map=2/0/20)

Después de una larga búsqueda, encontramos el nodo que coincide a la perfección.

![ubi_overpass_final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/overpass%20ubi%20final.png)

### De manera manual

Si buscamos de manera manual, podemos ir probando con Chatgpt y por búsquedas de Google Lens, pero no encontrábamos nada certero solo suposiciones. A una desesperada, si buscabamos justo por la colina del lugar, encontramos la solución.

![img_a_buscar](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/Busq_final.png)

Buscando la anterior imagen en Google Lens, encontramos lo siguiente

![busqueda](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/busqueda.png)

Dicha colina pertenece a un monumento llamado `Alligator Mound` el cual es un lugar de interés histórico ya que parece que la colina contiene un lagarto enorme en cima.

![articulo_colina](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/post.png)

Por tanto, ya tenemos la ubicación final. 417 Bryn Du Dr, Granville, OH 43023

![google_maps_final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Osint/The%20Blueprint/img/loc_final.png)

## Flag
`UMDCTF{417 Bryn Du Dr, Granville, OH 43023}`