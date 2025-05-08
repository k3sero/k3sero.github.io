---
title: The Needle - Hardware HackThebox
author: Kesero
description: Reto Hardware basado en extraer archivos provenientes de un firmware
date: 2025-05-08 10:00:00 +0000
categories: [Hack The Box, Hardware]
tags: [Writeups, Dificultad - Muy Fácil, Hardware, Hardware - Firmware, HTB, HTB - Hardware]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/assets/Hardware.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `MrR3boot`

Dificultad: <font color=green>Muy Fácil</font>

## Enunciado

"As a part of our SDLC process, we've got our firmware ready for security testing. Can you help us by performing a security assessment?"

## Archivos

Este reto nos da el siguiente archivo.

- `Firmware.bin` : Contiene el firmware mencionado en el enunciado.
- `Conexión por nc`: Contiene la conexión por nc del servidor.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/HackTheBox/Hardware/The-needle).

## Analizando el reto

Primero, vamos a lanzarle un `file` al binario para ver de qué se trata.

    ┌──(kesero㉿kali)-[~]
    └─$ file firmware.bin

    firmware.bin: Linux kernel ARM boot executable zImage (big-endian)

## Solver

En este reto, tenemos que encontrar las credenciales de acceso para acceder al servidor mediante la conexión por netcat proporcionada. Antes de nada, vamos a investigar el archivo `firwmare.bin`

Cuando tratamos con archivos `.bin` podemos extraer todos los archivos de su interior con el comando `binwalk - e`

    ┌──(kesero㉿kali)-[~]
    └─$ binwalk -e firmware.bin

Como hemos podido observar en el output, se nos creará una carpeta llamada `_firmware.bin.extracted` con todo el contenido extraido.

![Contenido](https://marcocampione.com/posts/202304-write-up-the-needle-htb/images/inside_folder.png)

Como podemos ver, tenemos muchos archivos que mirar. Para amenizar la búsqueda, podemos filtrar por usuarios y contraseñas con `grep`

    ┌──(kesero㉿kali)-[~]
    └─$ grep -rn "./" -e login

![filtrado](https://marcocampione.com/posts/202304-write-up-the-needle-htb/images/grep.png)

Si entramos en detalle, podemos observar que existe un usuario llamado `Device_Admin` por tanto tendremos que encontrar su contraseña. Para ello lanzamos el siguiente comando.

    ┌──(kesero㉿kali)-[~]
    └─$ find ./ -name sign

    ./sign
    ./squashfs-root/etc/config/sign

Como tenemos dos potenciales archivos, realizamos un `cat` de ambos y observamos la contraseña.

    ┌──(kesero㉿kali)-[~]
    └─$ cat ./squashfs-root/etc/config/sign

    qS6-X/n]u>fVfAt!

Listo! Mandamos las credenciales obtenidas a la instancia del reto, obtenemos una shell como `Device_Admin` y obtenemos la flag.

    ┌──(kesero㉿kali)-[~]
    └─$ nc 83.136.252.123 37357

    ng-985305-hwtheneedle-7khz5-85b986884d-lwkd6 login: Device_Admin
    Password: qS6-X/n]u>fVfAt!

    ng-985305-hwtheneedle-7khz5-85b986884d-lwkd6:~$ ls       
    flag.txt

    ng-985305-hwtheneedle-7khz5-85b986884d-lwkd6:~$ cat flag.txt

    HTB{4_hug3_blund3r_d289a1_!!}

## Flag

`HTB{4_hug3_blund3r_d289a1_!!}`