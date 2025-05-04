---
title: Insert coin to play Part [1-2] - UMDCTF2025
author: Kesero
description: Reto basado en hackear videojuegos para cambiar registros a nuestra voluntad
date: 2025-05-03 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, GamePwn]
tags: [GamePwn]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/prompt.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `sc0F`

Dificultad: <font color=green>Fácil</font>

## Introducción

En este post, se verán los retos `Insert coin to play Part 1` y `Insert coin to play Part 2`, ambos tematizados en el mismo ejercicio.

## Insert coin to play Part 1 

### Enunciado

"A lone cube awakens in an earthen box, the painted sky and silent peaks beckoning through the walls. The coin counter demands ten, but only five gleam in plain sight. Somewhere in the shadows of the game’s memory, the missing coins await discovery. Strike the counter’s memory until it reads “10,” and let the mystery unfold."

### Archivos

Este reto nos da el siguiente archivo.

- `Insert coin to play - Part 1.rar` : Carpeta de archivos necesarios para ejecutar el juego.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/prompt.png?raw=true).

### Analizando el reto

Una vez tengamos la carpeta descomprimida, tendremos que ejecutar el binario `GTA5.exe`.

![ejecu](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/ejecu.png?raw=true)

Nuestra misión será conseguir las 10 monedas para que el juego nos arroje la flag, pero es sencillo no?

### Solver

Como he mencionado anteriormente, tenemos que conseguir las 10 monedas, pero en el escenario en el que se encuentra nuestro personaje solo tenemos acceso a 5 de ellas, el resto no aparecerán.

Para conseguir modificar el registro del contador de nuestras monedas, utilizaremos el software `CheatEngine`

Para ello ejecutaremos nuestro binario.exe y ejecutaremos cheat Engine, para posteriormente añadir el proceso del binario.exe en CheatEngine y acto seguido ir filtrando por las direcciones de memoria.

Para ello, como el contador empieza por 0 monedas, buscaremos registros cuyas direcciones de memoria tengan 0 en su interior. Posteriormente cogemos una moneda y buscaremos la siguiente ocurrencia por un valor de 1 en el registro. Realizando el paso anterior varias veces, nos daremos cuenta de que solo tenemos 3 direcciones potenciales donde se guardan el contador de monedas.

Lo siguiente será cambiar el valor de los registros mencionados por 10 y acto seguido para actualizar el contador, cogeremos una de las monedas que quedan en el escenario

![Cheat_Engine](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/cheat.png?raw=true)

Al hacerlo, nos saldrá la flag por pantalla.

![flag_1](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/flag.png?raw=true)

### Flag
`UVT{L00ks_l1K3_Th3r3_w3R3_M0r3_c01N5}`


## Insert coin to play Part 2

### Enunciado

"A lone cube returns to the same earthen area where ten coins now glint at every corner. Nine surrender easily, but the tenth eludes your grasp, slipping through the cracks of reality until it vanishes. A secret forge exists, quietly stamping new coins for those who dare to listen."

### Archivos

Este reto nos da el siguiente archivo.

- `Insert coin to play - Part 2.rar` : Carpeta con los archivos necesarios para ejecutar el juego.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/prompt.png?raw=true).

### Analizando el reto

Una vez tengamos la carpeta descomprimida, tendremos que ejecutar el binario `GTA6.exe`.

![ejecu](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%201/img/ejecu.png?raw=true)

Nuestra misión será conseguir las 10 monedas para que el juego nos arroje la flag, pero es sencillo no?

### Solver

En este caso, en el escenario se encuentran las 10 monedas que necesitamos para que nos arroje la flag, pero justo cuando intentamos obtener la décima, esta moneda será como un imán con el personaje y nunca la podremos obtener, ya que la repeleremos. Al obtener la penúltima moneda obtendremos el siguiente mensaje.

![err_msg](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/err_msg.png?raw=true)

En este caso, utilizaremos nuevamente `CheatEngine` para resolver este reto, pero en vez de filtrar por direcciones de memoria para introducir valores a nuestra voluntad, utilizaremos la herramienta de hipervelocidad, para engañar al juego en el último momento y obtener la décima moneda forzando al juego a que no ejecute la función que repele la última moneda.

Para ello como tenemos 2 monedas en el suelo, tendremos que coger todas las demás para que en el último momento, activemos el cheat de la hipervelocidad y acto seguido recoger las dos últimas monedas del tirón.

![cheat_engine_hipervelocidad](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/paint2.png?raw=true)

Al hacerlo, obtendremos la flag por pantalla.

![flag2](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UniVsThreatsCTF2025/GamePwn/Insert%20coin%20to%20play/Insert%20coin%20to%20play%20-%20Part%202/img/flag2.png?raw=true)

### Flag

`UVT{Wh4t?!_D1d_Y0u_r3aLly_c4TcH_1t?}`