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
  path: 
  lqip: 
  alt: 
comments: true
---

Autor del reto: `CryptoCat`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"Does this login application even work?!

## Archivos

Este reto nos da los siguientes archivos.

- `babyflow` : Contiene el ejecutable a vulnerar.
- `nc babyflow.ctf.intigriti.io 1331` : Conexión por netcat al servidor del reto.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Pwn/1337UpCTF2024/BabyFlow).

## Analizando el código
