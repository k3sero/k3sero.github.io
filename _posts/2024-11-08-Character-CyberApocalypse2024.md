---
title: Character - CyberApocalypse2024
author: Kesero
description: Reto Miscelánea basado en hacer un breve script de conexión por nc.
date: 2024-11-08 21:54:00 +0800
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Muy Fácil, Script, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Misc/CyberApocalypse2024/Character/Character.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `ir0nstone`

Dificultad: <font color=green>Muy Fácil</font>

## Enunciado

"Security through Induced Boredom is a personal favourite approach of mine. Not as exciting as something like The Fray, but I love making it as tedious as possible to see my secrets, so you can only get one character at a time!"


## Archivos

En este reto, solamente nos dan una conexión por `netcat`, al conectarnos encontramos lo siguiente.

```sh
$ nc <ip> <port>
Which character of the flag do you want? Enter an index: 
```

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/CyberApocalypse2024/Character).

Si introducimos números de forma consecutiva por ejemplo `0`, `1` etc, podemos ver que ocurre lo siguiente.

```
Which character of the flag do you want? Enter an index: 0
Character at Index 0: H
Which character of the flag do you want? Enter an index: 1
Character at Index 1: T
Which character of the flag do you want? Enter an index: 2
Character at Index 2: B
```

Podemos observar que son los primeros tres caracteres de la flag `HTB` por lo que nos están dando la flag directamente solamente al introducir los índices.

## Solución

La solución es muy simple, simplemente introducimos los indices desde el $0$ hasta el tamaño de la flag de forma consecutiva y ya tendriamos la flag, pero en este caso vamos a realizar un breve script para familiarizarnos con este tipo de conexiones.

Solamente tenemos que crear una variable `flag`, introducir los índices cuando el programa nos lo pida e ir filtrando por la información que nos arroja para obtener la flag de forma dinámica. Para ello el código final es el siguiente.

```python
from pwn import *

p = remote('127.0.0.1', 1337)

flag = ''
idx = 0
while True:
    p.sendlineafter(b'index: ', str(idx).encode())
    p.recvuntil(b': ')
    char = p.recvS(1)

    flag += char
    idx += 1

    if char == '}':
        break

print(flag)
```

### NOTA

Tanto la función `sendlineafter` como `recvS` son muy útiles para scriptear el recibir/transmitir datos en una conexión de forma muy eficiente.


## Flag

`tH15_1s_4_r3aLly_l0nG_fL4g_i_h0p3_f0r_y0Ur_s4k3_tH4t_y0U_sCr1pTEd_tH1s_oR_els3_iT_t0oK_qU1t3_l0ng`

