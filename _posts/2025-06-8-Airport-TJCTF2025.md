---
title: Airport - TJCTF2025
author: Kesero
description: Reto basado en Geolocalizar un aeropuerto y obtener su identificación ICAO
date: 2025-06-08 17:00:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Osint, Osint - Geo, Otros - Writeups, Dificultad - Fácil, TJCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport/8.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `2027aliu`

Dificultad: <font color=orange>Fácil</font>

## Enunciado

"i made a mIstake and got lost, i always lose traCk of where i am oh no somebody kidnApped me please find where i am save me before i gO on this horrific plane tjctf{uppercasecode}"

## Archivos

Este reto tenemos el siguiente archivo.

- `lost.png`: Contiene la imagen del aeropuerto.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport).

![lost](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport/lost.png)

## Analizando el reto

Si analizamos el enunciado, podemos observar un comportamiento anómalo  y es que hay letras que están en mayúsculas en el propio enunciado.

Si unimos cada letra, nos damos cuenta que se forma la palabra `ICAO`

`ICAO` (Organización de Aviación Civil Internacional), es un organismo especializado de las Naciones Unidas que se encarga de establecer normas y regulaciones internacionales para la aviación civil en todo el mundo. Cada aeropuerto tiene su propia identificación `ICAO`. Por ejemplo, el aeropuerto de Madrid-Barajas tiene un código `ICAO` de LEMD.

En este caso, nos piden que introduzcamos el `ICAO` correspondiente al aeropuerto de la imagen.

## Solver

Si analizamos la imagen, podemos observar como hay palabras escritas en español, esto nos puede ayudar a descartar aeropuertos y quedarnos únicamente con lugares donde se hable el castellano, como puede ser en Latinoamérica o España.

Además, en este tipo de ejercicios, siempre podemos afinar aún más nuestra búsqueda utilizando `Google Lens` y `Chatgpt` para afinar nuestro rango de ubicaciones.

Al hacerlo, encontramos que el aeropuerto se llama "Nuevo Aeropuerto Internacional Jorge Chávez" perteneciente a Perú.

![find](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/airport/aereopuerto%20peru.png)

Una vez encontrado el aeropuerto, obtenemos su `ICAO` y lo convertimos al formato de la flag. En este caso se corresponde con SPJC.

## Flag
`tjctf{SPJC}`