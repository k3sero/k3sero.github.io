---
title: GeoGuessitUdine - SnakeCTF2025 Final
author: Kesero
description: Reto basado en geolocalizar un pueblo con una subestación eléctrica especial en Udine
date: 2025-12-09 17:30:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Osint, Osint - Geo, Otros - Writeups, Dificultad - Fácil, SnakeCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitUdine/14.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Michele Lizzit`

Dificultad: <font color=green>Fácil</font>

## Enunciado

```
Geoguess it. It's easy. It's in the Udine province.

We have found a place full of snakes. We sent our photographer to take a picture
but he got lost. He sent us two pictures, can you locate where the first one was taken?
```

## Archivos

```
pic1.png
```

![pic1.png](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitUdine/pic1.png)

```
pic2.png
```

![pic2.png](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitUdine/pic2.png)


Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitUdine).



## Analizando el reto

La zona mostrada se corresponde con un pueblo rural que posee una subestación eléctrica compacta vertical característica de la zona de `Udine`. Además, se observa una fuente especial dentro de una especie de plaza en la zona.


## Solver equipo

En este caso, el reto se resolvió buscando ocurrencias de la fuente en Google Images. Al hacerlo, se mostraban imágenes del pueblo en cuestión. Una vez se encontró el pueblo, se buscó el lugar exacto de las imágenes para establecer la localización.

![mapa](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitUdine/mapa_final.png)

![final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitUdine/final1.png)

## Solver desarrolladores

En este caso, haciendo uso de la herramienta online [Overpass](https://overpass-turbo.eu/) para el filtrado masivo de lugares en específico, se puede resolver el reto filtrando por fuentes especiales y por estaciones eléctricas en la región de `Udine`.

El script es el siguiente:

```
[out:json][timeout:25];

area
  ["boundary"="administrative"]
  ["admin_level"="6"]
  ["name:fur"="Udin"]
  ->.udine;

(
  node["power"~"substation|transformer"](area.udine);
  way ["power"~"substation|transformer"](area.udine);
)->.p;

(
  node    ["historic"="monument"](area.udine);
  way     ["historic"="monument"](area.udine);
  relation["historic"="monument"](area.udine);
)->.m;

(
  node    ["amenity"="drinking_water"](area.udine);
  way     ["amenity"="drinking_water"](area.udine);
  relation["amenity"="drinking_water"](area.udine);
)->.drink;

(
  node    ["leisure"="playground"](area.udine);
  way     ["leisure"="playground"](area.udine);
  relation["leisure"="playground"](area.udine);
)->.playgrounds;

nwr.playgrounds(around.drink:50)->.s1;
nwr.s1(      around.m:50    )->.s2;
nwr.s2(      around.p:50    )->.result;

(
  .result;
);
out body;
>;
out skel qt;
```

![final_overpass](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/GeoGuessitUdine/loc.png)

## P.D

En la página oficial de [SnakeCTF](https://snakectf.org/writeups), podrás encontrar todas las resoluciones oficiales.

## Flag
`snakeCTF{Dr1nk1ng_W4t3r!!!cb1b03bf92b0b94b}`