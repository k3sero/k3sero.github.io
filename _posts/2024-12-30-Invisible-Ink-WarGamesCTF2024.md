---
title: Invisible Ink - WarGamesCTF2024
author: Kesero
description: Reto Estego basado en la extración de información oculta de un archivo.gif.
date: 2024-12-30 15:15:00 +0800
categories: [Writeups Competiciones Internacionales, Estego]
tags: [ gif, Fácil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/3.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Yes`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"The flag is hidden somewhere in this GIF. You can't see it? Must be written in transparent ink."

## Archivos

En reto nos da el siguiente archivo.

- `challenge.gif` : Contiene un archivo .gif.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink).

## Analizando el código

En este reto basicamente tenemos que extraer la información del gif aportado. Si abrimos dicho archivo, nos encontraremos con un mensaje sin mayor relevancia.

![challenge](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/gif.png?raw=true)


## Solución

En este caso se tenía que utilizar stegsolve para obtener todos los frames que contaba dicho gif, ya que si queremos extraerlos con herramientas como Pillow, nos da error debido a la gran cantidad de pixeles que contiene el gif. (Pill sólo obtenía los frames 0, 1, 2 y 3 pero nos arrojaba que los frames resultantes superaba el máximo de píxeles permitidos)


Para ello teníamos que obtener los frames 4 y 5 a partir de esta herramienta y posteriormente combinarlos con herramientas de edicción de imágenes (en mi caso utilicé GIMP).

![Frame5](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/frame5.png?raw=true)

![Frame6](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/frame6.png?raw=true)

Finalmente para obtener la flag tenemos que combinar los frames anteriores.
En Gimp simplemente tenemos que añadir cada imágen a una capa diferente, no sin antes aplicar un color distinto a cada frame, para que el resultado sea mucho más visible que en blanco y negro.

![Final](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/WarGamesCTF2024/Invisible-Ink/final.png?raw=true)

## Flag

`wgmy{d41d8cd98f00b204e9800998ecf8427e}`