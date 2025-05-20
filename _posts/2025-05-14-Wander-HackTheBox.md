---
title: Wander - Hardware HackThebox
author: Kesero
description: Reto basado en inyectar comandos con PJL en un servicio de impresión online.
date: 2025-05-14 10:00:00 +0000
categories: [Hack The Box, Hardware - HTB]
tags: [Writeups, Dificultad - Fácil, Hardware, Hardware - PJL, HTB, HTB - Hardware]
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

Dificultad: <font color=green>Fácil</font>

## Enunciado

"My uncle isn't allowing me to print documents. He's off to vacation and I need a PIN to unlock this printer. All I found is a web server where this printer is managed from. Can you help me with this situation ?"

## Archivos

En este reto, tenemos el siguiente enlace.

- `instancia vía web`: Contiene la instancia del reto web.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/HackTheBox/Hardware/Wander).

## Analizando el reto

Si introducimos la dirección dada en el reto, podemos observar la siguiente página de entrada.

![portada](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Wander/portada.png)

En ella se listan opciones como `Dashboard`, `Network`, `Job Controls` y `Help` pero realmente solo está disponible la sección de Job Controls.

Si nos adentramos en ella podemos observar el siguiente apartado.

![job](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Wander/job.png)

## Solver

Si nos fijamos en la sección `Job Controls` podemos introducir algo relacionado con `@PJL INFO ID`, pero ¿qué es esto?

Los comandos PJL (Printer Job Language) son un conjunto de instrucciones desarrolladas por Hewlett-Packard (HP) que permiten controlar impresoras más allá de lo que permite el lenguaje de impresión como PCL o PostScript. Por ejemplo, algunos de los comandos que nos permite este lenguaje son los siguientes.

1. Cambiar configuraciones de la impresora (idioma, bandeja, tamaño de papel, etc.)

2. Consultar el estado de la impresora.

3. Administrar trabajos de impresión.

4. Interactuar con el panel de control.

5. Ejecutar comandos de red o incluso, en algunos casos, acceder al sistema de archivos de la impresora.

Un ejemplo detallado de cómo funcionaría sería el siguiente, el cual primero se inicia la secuencia, se indica el inicio del trabajo, acto seguido se configura los parámetros de impresión y por último se cambia el lenguaje de impresión.

```
<ESC>%-12345X@PJL JOB
@PJL SET PAPER=A4
@PJL SET COPIES=2
@PJL ENTER LANGUAGE=PCL
... datos PCL ...
<ESC>%-12345X
```

Además, recomiendo visitar la [página oficial de HP](https://developers.hp.com/hp-printer-command-languages-pcl/doc/print-job-language-pjl) donde explican más en detalle el lenguaje. También si estás aburrido, te dejo la [documentación oficial](https://developers.hp.com/system/files/attachments/PJLReference%282003%29_0.pdf) de más de 300 páginas por si quieres profundizar en el tema.

Una vez comprendido lo que son los comandos `PJL`, ¿qué toca hacer ahora?

Pues básicamente, vamos a ir probando comandos para ver cómo se comporta el servidor en cuestión.

Por ejemplo, siguiendo la documentación podemos probar con los siguientes comandos.

```
FSAPPEND
FSDELETE
FSDIRLIST
FSDOWNLOAD
FSINIT
FSMKDIR
FSQUERY
FSUPLOAD
```

Por ejemplo, para ver el directorio actual utilizaremos `FSDIRLIST` con el siguiente comando.

```
@PJL FSDIRLIST NAME="0:" ENTRY=1
```

![dirlist](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Wander/dirlist.png)

Mediante este comando, también podemos listar contenido no solo del directorio actual, sino de cualquier ruta del sistema. Para ello utilizaremos la siguiente sintaxis.

```
@PJL FSDIRLIST NAME="0:/../" ENTRY=1
```

![cualquier_list](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Wander/cualquierlist.png)

Si seguimos listando contenido mediante el anterior comando, podemos observar como en la carpeta `home` se encuentra un directorio `default` con un archivo `readyjob`.

En este caso, para leer dicho archivo, tenemos que utilizar el comando `FSUPLOAD` mediante la siguiente sintaxis.

```
@PJL FSUPLOAD NAME="0:/../home/default/readyjob" ENTRY=1
```

Al hacerlo, obtenemos la flag.

![flag](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Wander/flag.png)

## Flag
`HTB{w4lk_4nd_w0nd3r}`