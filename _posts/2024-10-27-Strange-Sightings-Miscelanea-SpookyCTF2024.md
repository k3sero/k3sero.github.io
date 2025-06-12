---
title: Strange Sightings - SpookyCTF2024
author: Kesero
description: Reto miscelánea basado en analizar un video de YT.
date: 2024-10-27 19:47:00 +0800
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Dificultad - Media, Otros - Writeups, SpookyCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Misc/Spookyctf2024/Strange_Sightings/Strange_Sightings.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Cyb0rgSw0rd`

Dificultad: <font color=orange>Media</font>

# Enunciado

"NICC agents were sent this video by an anonymous source. What does it mean?!

Warning: The video is very spooky."


# Archivos

En este reto solo nos dan un enlace a un video de YouTube.

- `https://www.youtube.com/watch?v=4Xv8pLoDVP0`: "Strange Sightings"

Video [aquí](https://drive.google.com/file/d/1lCyRp8TWrhw3XPwhtGK6F317hfYmq0fz/view?usp=sharing).

## Analizando el reto

En este reto, básicamente tenemos un vídeo de 12 minutos el cual está basado en diversos clips con temática de terror de alrededor de 15 segundos cada uno en los que se van mostrando diversos lugares. ¿Alguna idea con estos retos?

Este tipo de retos se basan principalmente en descubrir pequeños detalles ocultos dentro de dichos clips, hay que analizarlo una y otra vez para encontrar alguna serie de patrones o pistas que nos lleven a la flag.

Es por ello que hay que tener mucha paciencia con ellos y visualizarlos detenidamente.

## Solución

En este caso se encuentran diversas pistas relevantes a lo largo de la duración de los clips.

1. Al comienzo se muestran carcteres de forma rápida los cuales uniéndolos forman la frase "COME GET YOUR FILE"
2. Hay varias partes donde un hombre habla durante algunos segundos, pero esta pista no termina de ser relevante.
3. A partir del minuto 7:20 se muestran unas lámparas que parpadean continuamente de forma errática ¿Casualidad?

Después de analizar detenidamente dichos parpadeos, podemos intuir que dicha lámpara está mostrando un mensaje en `código morse`.

Básicamente el código Morse es un sistema de comunicación que representa letras, números y signos mediante combinaciones de puntos y rayas (cortas y largas) donde los puntos se suelen definir con 1 duración y las rayas con el doble de la duración de un punto.

Es por ello que extrayendo dicha información de la lámpara obtenemos lo siguiente.

    .---- ...-- --... .-.-.- .---- ---.. ....- .-.-.- ..... --... .-.-.- .---- ---.. --...

Utilizando herramientas como `CyberChef` o de forma manual, podemos observar el siguiente texto en claro.

    137.184.57.187

A partir de este punto se nos puede venir a la cabeza realizar miles de cosas con esa IP, pero primero de todo se me ocurrió geolocalizarla para saber si ibamos en buen camino o se trataba de un lugar sin salida y descubrimos que dicha IP pertenece a un servicio de Hosting llamado DigitalOcean encontrándose en Estados Unidos New Jersey.

Recordad, que una de las pistas nos dice "COME GET YOUR FILE" por lo que tenemos que encontrar un fichero con esa IP ¿Alguna idea?

Pues básicamente lo que nos están pidiendo que hagamos es que nos conectemos por FTP a dicha IP y nos traigamos la `flag.txt`. Es por ello que hice lo siguiente.

    ┌──(kesero㉿kali)-[~]
    └─$ ftp 137.184.57.187

    Connected to 137.184.57.187.
    220 Boo!
    Name (137.184.57.187:kali): dir
    530 This FTP server is anonymous only.
    ftp: Login failed

    ftp> cd
    (remote-directory) cd
    530 Please login with USER and PASS.

    ftp> user
    (username) anonymous
    230 Login successful.
    Remote system type is UNIX.
    Using binary mode to transfer files.

    ftp> dir
    229 Entering Extended Passive Mode (|||47926|)
    150 Here comes the directory listing.
    -rw-r--r--    1 ftp      ftp            56 Oct 25 19:24 flag.txt
    226 Directory send OK.

    ftp> get flag.txt
    local: flag.txt remote: flag.txt
    229 Entering Extended Passive Mode (|||31580|)
    150 Opening BINARY mode data connection for flag.txt (56 bytes).
    100% |*************************************************************************************************************************************************|    56        0.13 KiB/s    00:00 ETA
    226 Transfer complete.
    56 bytes received in 00:00 (0.08 KiB/s)

    ftp> exit
    221 Goodbye.

Abrimos el archivo y leemos la flag.


## Flag

`NICC{I_h0p3_whatever_is_in_the_backrooms_brought_candy}`