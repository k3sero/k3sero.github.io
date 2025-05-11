---
title: The Mini - UMDCTF2025
author: Kesero
description: Reto basado escapar de un programa 
date: 2025-05-11 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Writeups, Dificultad - Media]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Misc/Standard-Editor/img/2.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `evan`

Dificultad: <font color=green>Media</font>

## Enunciado

"Joel Fagliano has nothing on me. (flag is all caps)"

## Archivos

Este reto nos da el siguiente archivo.

- `conexión por netcat` : Contiene la conexión directa con el servidor del reto.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/Damctf2025/Misc/Standard-Editor).

## Analizando el reto

Al conectarnos por netcat podemos ver el siguiente mensaje.

```
    ┌──(kesero㉿kali)-[~]
    └─$ nc standard-editor.chals.damctf.xyz 6733

    [Sun May 11 20:22:15 UTC 2025] Welcome, editor!
    Feel free to write in this temporary scratch space.
    All data will be deleted when you're done, but files will
    first be printed to stdout in case you want to keep them.
    
    a
    ?
    b
    ?
    c
    ?

```

En cada input del usuario, el programa nos devuelve el caracter `?`

## Solver

## Flag
``