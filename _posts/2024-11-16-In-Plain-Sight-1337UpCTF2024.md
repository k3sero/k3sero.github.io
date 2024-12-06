---
title: In Plain Sight - 1337UP LIVE CTF2024
author: Kesero
description: Reto de Esteganografía basado en recuperar datos incrustados de diferentes archivos.
date: 2024-11-16 19:55:00 +0800
categories: [Writeups Competiciones Internacionales, Esteganografía]
tags: [Esteganografía, Writeups, incrustado]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/In_plain_sight.jpg?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `CryptoCat`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"Barely hidden tbh.."

## Archivos

En este reto, solo nos dan el siguiente archivo.

- `meow.jpg` : Fichero de imagen.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight).


## Analizando la imagen

El archivo que nos dan se corresponde con la imagen de un gato.

![Gato](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/meow.jpg?raw=true)

Aparentemente tenemos que encontrar algo de información en esta imagen, para ello iremos jugando con distintas herramientas como `exiftool`, `binwalk`, `zsteg`, `stegseek`, `stegsnow`, `strings`, `file` para tratar de recuperar datos incrustados en dicha imagen.


## Solución

El primer paso que deberemos de hacer es ejecutar la herramienta `binwalk` la cual nos mostrará la siguiente información.

    ┌──(kesero㉿kali)-[~]
    └─$ binwalk meow.jpg


    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    2144878       0x20BA6E        Zip archive data, encrypted at least v2.0 to extract, compressed size: 1938, uncompressed size: 3446, name: flag.png
    2146976       0x20C2A0        End of Zip archive, footer length: 22

Como podemos ver, dicha imagen contiene un archivo `.zip` con información en su interior, para extraer dicho `fichero.zip` utilizaremos el parámetro `-e`.

    ┌──(kesero㉿kali)-[~]
    └─$ binwalk -e meow.jpg

    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    2144878       0x20BA6E        Zip archive data, encrypted at least v2.0 to extract, compressed size: 1938, uncompressed size: 3446, name: flag.png

Una vez extraído dicho fichero, se nos creará una carpeta llamada `_meow.jpg.extracted` donde estará dicho fichero zip.

Al intentar descomprimir dicho fichero zip, nos piden una contraseña para poder hacerlo, es por ello que en este punto tendremos que seguir probando con herramientas e ir jugando un poco con ellas.

En este caso la contraseña se encontraba dentro de la imagen `meow.jpg`, simplemente lanzando un `string` a la imagen, podemos ver la contraseña.

    YoullNeverGetThis719482

Una vez tenemos la contraseña, descomprimimos el fichero `.zip` y obtenemos un archivo llamado `flag.png` el cual se corresponde con la siguiente imagen.

    ┌──(kesero㉿kali)-[~]
    └─$ unzip -P YoullNeverGetThis719482 20BA6E.zip
    
    Archive:  20BA6E.zip
    inflating: flag.png 

![flag.png](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/flag.png?raw=true)

Podemos observar lanzando un `file`, que efectivamente se corresponde con el formato de una imagen .png la cual contiene información en su interior. Es por ello que nuevamente deberemos de seguir jugando con las distintas herramientas esteganográficas. 

Por último, el siguiente paso que hay que dar viene dado por observar las distintas capas que contiene dicha imagen con herramientas como `Gimp`, `Photoshop`, las cuales permiten obtener una descomposición en sus capas mostrando información contenida en ellas. A su vez, podemos jugar con el brillo y el contraste para observar posibles cambios en la imagen.

En mi caso, yo utilicé la herramienta `convert` la cual extrae la posible información existente en las capas de una imagen aparentemente oculta. Es por ello que ejecuté el siguiente comando.

    ┌──(kesero㉿kali)-[~]
    └─$ convert flag.png -auto-level output.png

Abrimos la imagen y efectivamente, encontramos la flag.

![output.png](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/1337UpCTF2024/In_Plain_Sight/output.png?raw=true)

### NOTA

Mirando otros Writeups, hay gente que lanza busquedas de Estego online mediante el siguiente enlace: [https://georgeom.net/StegOnline/image ](https://georgeom.net/StegOnline/image )

## Flag

`INTIGRITI{w4rmup_fl46z}`