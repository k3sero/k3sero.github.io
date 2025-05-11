---
title: More Sleuth - UMDCTF2025
author: Kesero
description: Reto basado en encontrar el avión fantasma dentro de un reporte de radio
date: 2025-05-11 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Writeups, Dificultad - Media]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Misc/Mode%20Sleuth/img/3.png
  lqip: 
  alt: 
comments: true
---
Autores del reto: `KeKoa_M, alienfoetus`

Dificultad: <font color=green>Media</font>

## Enunciado

"Software defined radio is so fun! I just recorded a bunch of planes near me, but I think someone messed with the data. Can you find the plane that is not supposed to be there?

Flag format: dam{<N-number>_<Registered owner name>_<serial number>}

Note: must be all caps, owner name should be full name including any spaces Example: dam{N249BA_BOEING AIRCRAFT HOLDING CO_24309}"

## Archivos

Este reto nos da el siguiente archivo.

- `captura.txt` : Contiene la captura de radio de los logs de aviones.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Misc/Mode%20Sleuth).


## Analizando el reto

En la `captura.txt` podemos encontrar la siguiente información.

```
*8DA37DB958BF0299ECD4CFB09C63;
*8DA37DB99911BD8DD80414F5B235;
*02E197B0E91C84;
*5DAB8D760E80DC;
*02E19338DEACE7;
*8DAB8D76589B82A3FD2E748E7900;
*8DAB8D769915579790040EA86431;
*8DAB8D76EA3AB860015F48BFFCAD;
*20001338D874AD;
*02E19338DEACE7;
*5DAB8D760E80DF;
*02E61338069104;
*02E19338DEACE7;
*8DAB8D76589B86322DA4C2393F69;
*8DAB8D769915579790080EE03E31;
*5DAB8D760E80DC;
*8DAB8D76589B86320DA4A781CDAF;
*02E19338DEACE7;
*8DAB8D76EA3AB860015F48BFFCAD;
*8DAB8D76589B82A3932E1601F83E;
*8DAB8D769915579790080F1FCA38;

(...)
```

## Solver

## Flag
``