---
title: Gunnar´s Vacation Pictures[1-7] - THCON2025
author: Kesero
description: Compilación de retos asociados a la búsqueda de posición en base a imágenes en Google Maps
date: 2025-04-14 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Osint]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/prompt.png?raw=true
  lqip: 
  alt: 
comments: true
---


## Introducción

En este post, se recogen 7 retos asociados a la búsqueda de la posición exacta de unas imágenes dadas en Google Maps. En caso de acertar con la posición, obtenemos la flag.

A pesar de ser una serie de ejercicios básicos, he decidido hacer writeup de todos ellos para conocer en exactitud las herramientas y metodologías utilizadas para resolver este tipo de ejercicios basados en Geoguess.

1. Búscador de imágenes por Google.
2. Chatgpt ayuda enormemente a la hora de realizar estos ejercicios.
3. Páginas web de triangulación en base al kilometraje como [smappen](https://www.smappen.com/app/)
4. Scripts manuales de búsqueda en Google Maps con filtros específicos.
5. Páginas web basadas en IA como [Picarta]() (0% de aciertos) o [GeoSpy]()(No probada por tener los registros cerrados)
6. [GeoHints](https://geohints.com/) es una página basada en ofrecer posibles ubicaciones en base a las diferentes pistas y objetos de un lugar en cuestión. Muy usada por expertos de GeoGuesser.

A la hora de visualizar mapas se pueden utiizar las siguientes herramientas.

1. [Google Maps](https://www.google.com/maps/), mayor velocidad de búsqueda y más compacto
2. [Google Earth](https://earth.google.com/web/), más lento pero permite visualizaciones 3D del entorno
3. [Panoramax](https://panoramax.openstreetmap.fr/), alternativa a las dos anteriores (es francesa)

## Enunciado 

"It looks like Gunnar (a.k.a "The Executioner") has given his fellow gang members the slip and ran away with the money they extorted from the THBank !

We are lucky to have some access to The Razor's infrastructure, and it he seems to have access to some glimpses of Gunnar's cybernetic eyes. The XSS are effectively tracking him and the website we discovered is probably used to get minions to find the locations of the fugitive under the supervision of a - particular - AI called glad0s (how original !).

Try leveraging this platform to locate as many pictures as possible of places where Gunnar has been during his trip, so we can look at CCTV footage and perhaps guess where he'll go next.

For your sanity (and copyright reasons) we have disabled the music that the Ai was playing constantly but if you want to have the full experience here it is :"

Básicamente el lore de estos ejercicios se trata en seguir la pista de un cibercriminal en base a unas imágenes aportadas por la organización. A medida que vamos resolviendo retos nos damos cuenta de que todos ellos se basan en la costa mediterránea con más detalle en Francia, concretamente en la costa azul y Córcega.

## Picture 1 (Easy)

![1](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/1.jpg?raw=true)

Básicamente si buscamos el nombre del hotel en Google, obtendremos la ubicación