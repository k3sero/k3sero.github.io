---
title: The Mini - UMDCTF2025
author: Kesero
description: Reto basado en descifrar un crucigrama basado en el juego The Crossword.
date: 2025-04-27 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Otros - Writeups, Dificultad - Fácil, UMDCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Misc/the-mini/img/the-mini.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `aparker`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"Joel Fagliano has nothing on me. (flag is all caps)"

## Archivos

En este reto, tenemos el siguiente archivo.

- `the-mini.puz`: Contiene el crucigrama en formato `.puz`

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Misc/the-mini).


## Analizando el reto

En este reto nos dan un crucigrama del juego The Crossword. Este crucigrama pertenece a la versión mini de dicho juego ya que cuenta con una cuadrícula de 5x5.

En el enunciado se menciona el autor de varios juegos de puzzles llamado `Joel Fagliano`. Uno de ellos es el mencionado anteriormente `Mini Crossword`

## Solver

Para abrir archivos en formato `.puz` utilizaremos la herramienta online [communicrossings.com](https://communicrossings.com/files/crossword/puz/derekslager/puz.html) la cual nos permitirá realizar el crucigrama de manera interactiva.

![img_crucigrama](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Misc/the-mini/img/img_crucigrama.png)

Al resolverlo finalmente, podremos llegar a la conclusión de que no hay una flag o una cadena legible, es por ello que Daysa en este momento, perdió la mitad de sus increíbles neuronas (haciendo retos de Misc y no de Crypto).

Además si directamente ejecutamos `xxd` con el archivo proporcionado, podemos obtener la solución directa pero en este caso no tiene relevancia alguna.

La resolución de este ejercicio viene dada por desbloquear la solución final en base a una cadena.

Para ello con un simple script en python podemos desbloquear la solución en base a un entero iterable, hasta que obtengamos la solución que en este caso es la flag.

El script es el siguiente.

```py
import puz

p = puz.read('the_mini.puz')

for i in range(1000000):
    if p.unlock_solution(i):
        print(i)
        print(p.solution)
```

Al ejecutarlo, después de varias iteraciones encontramos la solución.

    ┌──(kesero㉿kali)-[~]
    └─$ python solver.py

    UMDCTFCANYOUBEATMYTIME...
    8
    UMDCTFCANYOUBEATMYTIME...
    9
    UMDCTFCANYOUBEATMYTIME...
    10
    UMDCTFCANYOUBEATMYTIME...

## Flag
`UMDCTF{CANYOUBEATMYTIME}`