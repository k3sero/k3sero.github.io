---
title: Stop Drop and Roll - CyberApocalypse2024
author: Kesero
description: Reto Miscelánea basado en hacer un script de automatización en base a unas directrices.
date: 2024-11-08 21:54:00 +0800
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Dificultad - Fácil, Misc, Misc - Scripts, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Misc/CyberApocalypse2024/Stop_Drop_and_Roll/Stop.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `ir0nstone`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"The Fray: The Video Game is one of the greatest hits of the last... well, we don't remember quite how long. Our "computers" these days can't run much more than that, and it has a tendency to get repetitive..."


## Archivos

En este reto, únicamente nos dan una conexión por netcat, al conectarnos encontraremos lo siguiente.

    $ nc localhost 1337
    ===== THE FRAY: THE VIDEO GAME =====
    Welcome!
    This video game is very simple
    You are a competitor in The Fray, running the GAUNTLET
    I will give you one of three scenarios: GORGE, PHREAK or FIRE
    You have to tell me if I need to STOP, DROP or ROLL
    If I tell you there's a GORGE, you send back STOP
    If I tell you there's a PHREAK, you send back DROP
    If I tell you there's a FIRE, you send back ROLL
    Sometimes, I will send back more than one! Like this: 
    GORGE, FIRE, PHREAK
    In this case, you need to send back STOP-ROLL-DROP!
    Are you ready? (y/n) 

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/CyberApocalypse2024/Stop_Drop_and_Roll).

## Analizando el código

Las instrucciones son muy simples. Simplemente el programa nos dirá `GORGE`, `PHREAK` o `FIRE` y nosotros tendremos que enviar la cadena `STOP`, `DROP` or `ROLL` dependiendo de lo que nos diga el programa.

## Solución

Lo que deberemos de hacer es programar un script el cual reciba la cadena indicada por parte del servidor y nosotros mapearemos el siguiente esquema.

* Si el programa nos dice `GORGE` enviamos `STOP`.
* Si el programa nos dice `PHREAK` enviamos `DROP`.
* Si el programa nos dice `FIRE` enviamos `ROLL`.

Además, tendremos que tener en cuenta que hay ocasiones en las que nos dice las cadenas concatenadas con varios casos simultáneos y nosotros tenemos que ser capaces de interpretarlas y de generar su correspondiente salida.

El script que utilicé para resolver el ejercicio fue el siguiente.

```python
from binascii import crc32
from pwn import *

def intercambiar_cadenas(cadena):
    # Decodificar la cadena de bytes y dividirla en palabras separadas
    palabras = cadena.decode().strip("b'\n").split(', ')

    # Crear un diccionario para mapear las palabras
    mapeo = {'FIRE': 'ROLL', 'PHREAK': 'DROP', 'GORGE': 'STOP'}

    # Iterar sobre cada palabra y aplicar el mapeo si es necesario
    palabras_intercambiadas = [mapeo.get(palabra, palabra) for palabra in palabras]

    # Unir las palabras intercambiadas de nuevo en una cadena
    cadena_intercambiada = '-'.join(palabras_intercambiadas)

    # Codificar la cadena intercambiada de nuevo en bytes
    cadena_intercambiada_bytes = cadena_intercambiada.encode()

    return cadena_intercambiada_bytes

def intercambiar_cadenas2(cadena):
    # Decodificar la cadena de bytes y extraer lo que sigue después de "What do you do?"
    cadena = cadena.decode()
    indice = cadena.find("What do you do?")
    cadena = cadena[indice+len("What do you do?"):].strip()
    
    # Dividir la cadena en palabras separadas
    palabras = cadena.strip("b'\n").split(', ')

    # Crear un diccionario para mapear las palabras
    mapeo = {'FIRE': 'ROLL', 'PHREAK': 'DROP', 'GORGE': 'STOP'}

    # Iterar sobre cada palabra y aplicar el mapeo si es necesario
    palabras_intercambiadas = [mapeo.get(palabra, palabra) for palabra in palabras]

    # Unir las palabras intercambiadas de nuevo en una cadena
    cadena_intercambiada = '-'.join(palabras_intercambiadas)

    # Codificar la cadena intercambiada de nuevo en bytes
    cadena_intercambiada_bytes = cadena_intercambiada.encode()

    return cadena_intercambiada_bytes
 
r = remote('94.237.61.79',  49263)
print(r.recvuntil(b"Are you ready?"))
r.sendline(b"y")
print(r.recvline())

string = r.recvline()
print("La cadena leida es: ", string)
salida = intercambiar_cadenas(string)
print("la salida es: ", salida)
r.sendline(salida)

for i in range (0,500):
    string = r.recvline()
    print("La cadena leida es: ", string)
    salida = intercambiar_cadenas2(string)
    print("la salida es: ", salida)
    r.sendline(salida)
    print(i)

```

Como podemos ver, el servidor nos envia 500 cadenas las cuales nosotros tenemos que contestar de forma correcta para que nos arroje la flag.

### NOTA

Leyendo otros writeups, he visto un script el cual realiza el mismo procedimiento pero de manera más compacta. Lo comparto a modo de curiosidad.


```python
from pwn import *

p = remote('127.0.0.1', 1337)

p.sendlineafter(b'(y/n) ', b'y')
p.recvline()

while True:
    recv = p.recvlineS().strip()

    if 'GORGE' not in recv and 'PHREAK' not in recv and 'FIRE' not in recv:
        print(recv)
        break

    result = recv.replace(", ", "-")
    result = result.replace("GORGE", "STOP")
    result = result.replace("PHREAK", "DROP")
    result = result.replace("FIRE", "ROLL")

    p.sendlineafter(b'do? ', result.encode())
```

## Flag

`HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}`