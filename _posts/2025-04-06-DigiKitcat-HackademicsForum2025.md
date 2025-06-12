---
title: DigiKitcat - HackademicsForum2025
author: Kesero
description: Reto hardware basado en una PCB.
date: 2025-04-06 15:00:00 +0000
categories: [Writeups Competiciones Nacionales, Hardware N]
tags: [Hardware, Hardware - PCB, Otros - Writeups, Dificultad - Fácil, HackademicsForum]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Hardware/DigiKitkat/img/7.png
  lqip: 
  alt: 
comments: true
---

Nombre del reto: DigiKitcat.

Autor del reto: `Kesero`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"Mi gran amigo Joe Grand ha diseñado un dispositivo hardware capaz de realizar ataques de Keylogging.
Me ha dicho que ha guardado una sorpresa en él, pero no tengo ni idea de esto del hardware.
¿Me ayudas?"

## Archivos

En este reto, nos dan la siguiente carpeta.

- `gerber/` : Contiene los archivos `.gbr`

## Analizando el reto

En este reto tenemos una carpeta llamada `gerber` la cual contiene archivos `.gbr`. Este tipo de archivos son utilizados a la hora de realizar placas de circuitos impresos (PCBs). Estos archivos deben abrirse en un conjunto con aplicaciones dedicadas, ya que contribuyen individualmente a la representación visual de la PCB por capas.

Hay numerosas aplicaciones en las que podemos visualizar dichos archivos, como por ejemplo`KiCad`, `Gerbv`, `EasyEDA`, `PCBWay`, `ViewMate` o directamente con visualizadores online.

## Solución

Este reto trata de visualizar el diseño lógico de un circuito impreso, en este caso estamos tratando con la famosa `DigiSpark`.
Para ello tendremos que navegar entre las capas que conforman dicha PCB en busca de la flag. Esto lo podemos realizar con numerosas herramientas, como he mencionado anteriormente.

La manera más sencilla de manipular estos archivos es con la aplicación `KiCad`, ya que es gratuita y se instala de forma sencilla.

```
    ┌──(kesero㉿kali)-[~]
    └─$ sudo apt install kicad
```

Una vez instalada, abriremos la aplicación e iremos a `Visor Gerber`, y se nos abrirá una pestaña con todas las capas que conforman nuestra circuito impreso.

![placa](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Hardware/DigiKitkat/img/placa.png)

En este punto tendremos que navegar entre las distintas capas del circuito y es en la capa `Bottom Paste` donde se encuentra nuestra flag.

![capa](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Hardware/DigiKitkat/img/capa.png)

![flag](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Hardware/DigiKitkat/img/flag.png)

## Flag

`hfctf{¡B13nv3n1d0_A1_MuNd0_d3l_D1s3ño_h4rdwar3!}`