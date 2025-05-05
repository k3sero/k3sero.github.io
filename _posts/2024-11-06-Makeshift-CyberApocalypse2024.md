---
title: Makeshift - CyberApocalypse2024
author: Kesero
description: Reto Cripto basado en revertir una función de cifrado sencilla.
date: 2024-11-6 20:31:00 +0800
categories: [Writeups Competiciones Internacionales, Criptografía]
tags: [Cripto - Algoritmos, Dificultad - Muy Fácil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Makeshift/Makeshift.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `ir0nstone`

Dificultad: <font color=green>Muy Fácil</font>

## Enunciado

"Weak and starved, you struggle to plod on. Food is a commodity at this stage, but you can’t lose your alertness - to do so would spell death. You realise that to survive you will need a weapon, both to kill and to hunt, but the field is bare of stones. As you drop your body to the floor, something sharp sticks out of the undergrowth and into your thigh. As you grab a hold and pull it out, you realise it’s a long stick; not the finest of weapons, but once sharpened could be the difference between dying of hunger and dying with honour in combat."

## Archivos

En este reto nos dan dos archivos:

- `source.py` : Contiene el script de incriptación principal
- `output.txt` : El archivo de salida el cual contiene la flag rotada

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Makeshift).

## Analizando el código

Este ejercicio es muy simple, simplemente tenemos el siguiente código:

```python
from secret import FLAG

flag = FLAG[::-1]
new_flag = ''

for i in range(0, len(flag), 3):
    new_flag += flag[i+1]
    new_flag += flag[i+2]
    new_flag += flag[i]

print(new_flag)
```

Como podemos ver, este programa funciona de la siguiente forma.

1. Primero en la línea de código $FLAG[::-1]$ invierte la flag de forma que la parte principal pasa a la parte final y viceversa.

2. Posteriormente se recorre en un bucle for para tratar los caracteres en bloques de 3 en 3.

3. Por último cada bloque se trata de la siguiente manera. El segundo carácter es puesto en primera posición, el tercer carácter es puesto en la segunda posición y el primer carácter es puesto en la última posición. Por ejemplo si tenemos la cadena `YES` después de ejecutar esta función quedaría la cadena `ESY`.


# Solución

Básicamente para obtener la flag original, lo único que necesitamos hacer es invertir la cadena inversa que nos dan en el fichero `output.txt` nuevamente y ejecutar de nuevo las iteraciones mencionadas anteriormente ya que de este modo se ordenarían como estaban en un principio.

```python
flag = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
flag = flag[::-1]
plaintext = ''
 
for i in range(0, len(flag), 3):
    plaintext += flag[i+1]
    plaintext += flag[i+2]
    plaintext += flag[i]

print(plaintext)
```
## Flag

`HTB{4_b3tTeR_w3apOn_i5_n3edeD!?!}`