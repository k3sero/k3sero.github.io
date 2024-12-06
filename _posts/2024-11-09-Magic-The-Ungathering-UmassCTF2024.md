---
title: Magic the Ungathering - UmassCTF2024
author: Kesero
description: Reto Miscelánea basado en la interpretación de una cadena supuestamente codificada.
date: 2024-11-09 12:47:00 +0800
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Muy Fácil, Interpretación, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Magic_the_Ungathering/Magit_the_Ungathering.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `unknown`

Dificultad: <font color=green>Muy Fácil</font>

## Enunciado

"I took 2 much red40 while watchmaxxing spongebob and I forgor to write a welcome challenge. Now all I can see is this image burned into my retinas. WHAT DOES IT MEAN!?! (There is a word in this image, wrap it in `UMASS{}` to get the flag. Example: if the word was ALLIGATOR the flag would be UMASS{ALLIGATOR})"

## Archivos

En este reto solo tenemos el siguiente archivo.

- `image.jpg` : Contiene una imagen un tanto borrosa.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Magic_the_Ungathering).

## Analizando el código

Al abrir la imagen encontramos lo siguiente.

![Imagen](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Magic_the_Ungathering/image.png?raw=true)

Podemos observar que la imagen se encuentra un tanto borrosa y además, sabemos que dentro hay una palabra la cual tenemos que introducir dentro de la cadena UMASS{} para obtener la flag


# Solución

Este ejercicio es un calentamiento de la categoría Miscelánea y no hay que hacer literalmente nada. La flag viene ya escrita y son simplemente `sssssssss` puestas en la imagen pero son muy difíciles de leer. En total son unas 10 `S` puestas de manera secuencial.

## Flag

`UMASS{SSSSSSSSSS}`
