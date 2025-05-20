---
title: Invisible Ink - WarGamesCTF2024
author: Kesero
description: Reto Estego basado en la extracción de información oculta de un archivo.gif.
date: 2024-12-30 15:15:00 +0800
categories: [Writeups Competiciones Internacionales, Esteganografía]
tags: [Estego, Dificultad - Fácil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/Titulo.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Yes`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"The flag is hidden somewhere in this GIF. You can't see it? Must be written in transparent ink."

## Archivos

En este reto, solo nos dan el siguiente archivo.

- `challenge.gif` : Contiene un archivo .gif.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink).

## Analizando el código

En este reto básicamente tenemos que extraer la información del gif aportado. Si abrimos dicho archivo, nos encontraremos con un mensaje sin mayor relevancia.

![challenge](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/gif.png)


## Solución

En este caso, teníamos que utilizar [stegsolve](https://wiki.bi0s.in/steganography/stegsolve/) para obtener todos los frames que contaba dicho gif, ya que si queremos extraerlos con herramientas como Pillow, nos da error debido a la gran cantidad de píxeles que contiene el gif. (Pillow sólo obtenía los frames 0, 1, 2 y 3, pero nos decía que los frames resultantes superaban el máximo de píxeles permitidos)

Para ello teníamos que obtener los frames resultantes que es donde realmente está la información oculta. Para ello utilicé la herramienta mencionada anteriormente para la extracción de estos dos últimos frames.

![Frame5](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/frame5.png)

![Frame6](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/frame6.png)

Finalmente, para obtener la flag, tenemos que combinar los frames anteriores.
En Gimp, simplemente tenemos que añadir cada imagen a una capa diferente, no sin antes aplicar un color distinto a cada frame, para que el resultado sea mucho más visible que en blanco y negro.

![Final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/final.png)

## Flag

`wgmy{d41d8cd98f00b204e9800998ecf8427e}`