---
title: Evaldle - UMDCTF2025
author: Kesero
description: Reto basado en escapar de una pyjail para leer la flag.
date: 2025-04-27 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Misc - Pyjail, Otros - Writeups, Dificultad - Media, UMDCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Misc/evaldle/img/promp.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `aparker`

Dificultad: <font color=orange>Media</font>

## Enunciado

"The 2021 game of the year, now in pyjail form."

## Archivos

En este reto, nos dan los siguientes archivos.

- `nc challs.umdctf.io 31601` : Conexión por netcat al servidor
- `evaldle.py` : Contiene la lógica del servidor.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/Misc/evaldle).


## Analizando el reto

En `evaldle.py` encontramos el siguiente código.

```py
#!/usr/local/bin/python
f = open('flag.txt').read()

target = 'SIGMA'

while True:
    guess = input("Guess: ")
    if len(guess) != 5:
        print("Invalid guess.")
        continue
    for j in range(5):
        if target[j] == guess[j]:
            print('🟩', end='')
        elif guess[j] in target[j]:
            print('🟨', end='')
        else:
            print('⬛', end='')
    print('')
    try:
        exec(guess)
        print('🟩🟩🟩🟩🟩')
    except:
        print("🟥🟥🟥🟥🟥")
```

En resumidas cuentas, este código implementa un juego tipo Wordle que compara adivinanzas con la palabra secreta `SIGMA` dando pistas con emojis. Posteriormente, la cadena introducida por parte del usuario entra en la función `exec()`. Además podemos observar que tiene un bug en la lógica de pistas, ya que `target[j]` es una letra y no una colección, por eso solo se evalúa como verdadera si ambas letras son iguales (cubierto por la primera condición)

Hay un factor muy importante y es que el usuario está limitado a la cadena a introducir, ya que esta debe de ser de 5 caracteres para que se ejecute la función `exec()`, en caso contrario saltará el try.

## Solver

La solución de este reto viene dada por ejecución de la función `exec(guess)`
Además, podemos ver que a simple vista el contenido de `flag.txt` se encuentra embebido en la variable `f`

El código que nos proporcionan para este reto en particular, permite que cualquier texto introducido por el usuario, puede llegar a introducirse dentro de la función `exec()`, esto nos permite ejecutar código en el contexto del programa. Para ello, tendremos que reconstruir la bandera carácter por carácter sin adivinarla manualmente, usando una técnica de búsqueda binaria sobre un conjuto de caracteres posibles llamados `alpha`

Para ello, en cada intento tenemos que construir una string parcial y compararlo con la flag y en base si la flag es "menor" o "mayor" al string actual, el script provocará errores (como dividir entre False) además de observar si el programa responde con error (🟥🟥🟥🟥🟥) o éxito (🟩🟩🟩🟩🟩).

La clave de este proceso será el repetir este proceso hasta descubrir toda la bandera.

El script utilizado es el siguiente:

```py
from pwn import *
import string

alpha = sorted(string.ascii_letters + string.digits + '{}_')

with remote("challs.umdctf.io", 31601) as p:
    def guess(x):
        assert len(x) <= 5
        p.sendlineafter('Guess: ', x.ljust(5,'#').encode())
        p.readline()
        print(x.ljust(5,'#'))
        return p.readline() == b'\xf0\x9f\x9f\xa9'*5+b'\n'

    known = ''
    while not known.endswith('}'):
        low = 0
        high = len(alpha) - 1

        while low < high:
            mid = (low + high + 1) // 2
            guess("a=''")

            for c in known + alpha[mid]:
                guess(f"b='{c}'")
                guess("a+=b")

            guess("d=f<a")

            if guess("1/d"):
                high = mid - 1
            else:
                low = mid

        known += alpha[high]
        print(known)
```

Antes que nada, vamos a explicar paso por paso cada parte del código.

1. Lo más importante es entender y comprender el funcionamiento de `exec()`

Para ello, sabemos que `exec(guess)` va a ejecutar todo lo que escribamos como input (y tenga 5 caracteres). Por ejemplo, si ponemos `1+1`, el programa ejecutará `exec(1+1)`. Si pudieramos poner `exec(print(f))`, el programa nos devovlería la flag pero en este caso no aplica ya que input tiene más de 5 caracteres.

2. Nuestro principal objetivo es leer `f` que contiene la bandera, así que lo que tenemos que hacer es reconstruir la bandera carácter por carácter, comprobando realizando comprobaciones de si cierta letra está antes o después que otra en orden alfabético.

En Python podemos comparar strings de la siguiente forma.

```py
"abc" < "acd"  # True
```
Y posteriormente podemos hacer esto con las variables.
```py
if f < a:
    ...
```
Por lo tanto, podemos construir una variable `a` con algo como `UMDCTF{` y realizar la comparación anterior: " `f` es menor que `UMDCTF{`"?

Dependiendo de la respuesta que nos dé, podemos saber cual es el siguiente carácter correcto.

4. Tenemos que detectar la respuesta con errores, para ello sabemos que si: 

```py
d = f < a
1 / d
```
Si `d = True`, entonces `1 / d` = `1 / True` = `1 / 1` = Válido, no lanza error
Si `d = False`, entonces `1 / d` = `1 / False` = `1 / 0` = No válido, lanza error

Además, como el juego muestra 🟩🟩🟩🟩🟩 cuando no hay error, y 🟥🟥🟥🟥🟥 cuando sí hay error, podemos saber si `f < a`.

5. Por último, tenemos que realizar la operatoria anterior para todo el rango de caracteres y mediante un algoritmo de búsqueda eficiente, para ello utilizamos la `binary search` para encontrar el caracter correcto.

### P.D

Script original de `clam`. Es muy potente para futuros scripts basados en restricciones de caracteres.

## Flag

`UMDCTF{that_took_a_lot_more}`