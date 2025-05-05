---
title: Krusty Kathering - UmassCTF2024
author: Kesero
description: Reto Miscelánea basado en la creación de un script para automatizar órdenes.
date: 2024-11-09 13:22:00 +0800
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Dificultad - Fácil, Misc, Misc - Scripts, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Krusty_Kathering/Krusty_Kathering.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `unknown`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"Krusty Katering is hemorrhaging money, and Mr. Krabs has brought you in to fix it. You have 10 line cooks, and while they're okay at making Krabby patties, they can't agree on who cooks what and when. To make matters worse, Squidward (trying to keep his job) refuses to give you the list of orders, and will only tell you them one by one. Each time Squidward tells you a job, you get to add it to a cook's schedule for the day. Cooks cannot trade jobs, once it's on the schedule, it stays there. You want to ensure the last order finishes as soon as possible so that Mr. Krabs can close and count his profits. The competing Plankton's Provisions assigns their jobs randomly. So long as your crew is 20% more efficient than Team Chum Bucket every day this week, you're hired. Can you save Mr. Krabs' business?"

## Archivos

En este reto, solo tenemos una conexión por netcat.

- `nc krusty-katering.ctf.umasscybersec.org 1337` : Conexión por netcat.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Krusty_Kathering).

## Analizando el código

Al conectarnos mediante netcat al enlace proporcionado, obtenemos lo siguiente.

    == proof-of-work: disabled ==

    Krusty Katering is hemorrhaging money, and Mr. Krabs has brought you in to fix You have 10 line cooks, and while they're okay at making Krabby patties, they can't agree on who cooks what and when.
    To make matters worse, Squidward (trying to keep his job) refuses to give you the list of orders, and will only tell you them one by one.
    (...)
    The competing Plankton's Provisions assigns their jobs randomly.
    So long as your crew is 10% more efficient than Team Chum Bucket every day this week, you're hired.
    Can you save Mr. Krabs' business?

    ----------------------------------------

    Day 1. Time to beat: 10h24m45s

    Order #1: Pretty Patty Combo
    ├── Price: $18.50
    └── Estimated time to cook: 8m40s


    Which cook should handle this job? [1-10]

## Solución

En este ejercicio, lo que nos piden hacer es administrar una comanda de 10 cocineros asignando órdenes de comida a cada ellos, de manera en la que seamos un 10%-20% más eficientes que los cocineros de Plankton ya que él asigna las órdenes de forma aleatoria entre sus cocineros.

Cabe destacar que hay un total de 10 órdenes predefinidas que van llegando de forma aleatoria hacia nuestras cocinas recibiremos 1000 órdenes diarias durante un total de 5 días; cada orden tiene un tiempo establecido fijo, y contamos con un tiempo global que superar cada día (aunque no es relevante, ya que al automatizar el script no alcanzaremos dicho límite).

A partir de aquí, deberemos de superar una serie de días siendo un 10% más eficientes que cada día de Plankton pero, ¿Cómo lo hacemos?

Simplemente necesitamos encontrar un algoritmo de adminsitración de comandas más óptimo que la asignación de forma aleatoria. El más simple y óptimo es un algoritmo el cual asigne a todos los cocineros el mínimo de platos, de modo que todos estén ocupados el mismo tiempo, de esta forma no saturaremos de ordenes a un par de camareros ni dejaremos libres a otros.

Podemos definir el algoritmo a implementar como:

1. Las 10 primeras órdenes se asignan una órden a cada uno de los cocineros.
2. Una vez todos los cocineros tienen una orden, deberemos de calcular el tiempo de órden que tiene cada cocinero.
3. Se le asignará la siguiente orden al cocinero que tenga el tiempo de orden mínimo.
4. Repetimos el paso 2 y 3 en cada iteración.

Si adecuamos el algoritmo en la automatización de peticiones al servidor, obtendremos el siguiente código.


```py
from pwn import *
from tqdm import tqdm

r = remote("krusty-katering.ctf.umasscybersec.org", 1337)

orders = {b'Bran Flakes': 30,
          b"SpongeBob's Sundae": 370,
          b'Aged Patty': 600,
          b'Krabby Fries':450,
          b'Fried Oyster Skins':120,
          b'Holographic Meatloaf': 550,
          b'Seanut Brittle Sandwich': 90,
          b'Pretty Patty Combo': 520,
          b'Banana': 15,
          b'Popcorn': 60}

cookers = [0]*10

for _ in range(5):

  r.recvuntil(b"Time to beat: ")
  time_to_beat = r.recvuntil(b"\nOrder #1")[:-10]

  for i in tqdm(range(1000)):

    r.recvuntil(b": ")
    order = r.recvuntil(b"\n").strip()
    r.recvuntil(b"Estimated time to cook: ")
    time_order = r.recvuntil(b"\n").strip()

    r.recvuntil(b"Which cook should handle this job? [1-10]")
    index_cooker = cookers.index(min(cookers))
    r.sendline(str(index_cooker + 1).encode())
    cookers[index_cooker] += orders[order]
    r.recvuntil(b"\n\n")
    print(cookers)

r.interactive()

```

En el código, básicamente se define un diccionario con todas las órdenes que nos arroja el programa, para posteriormente asignarle el tiempo a el cocinero oportuno.

Luego, tenemos que crear un doble bucle, uno para controlar los 5 días de la jornada y el otro para satisfacer las 1000 órdenes diarias.En dicho bucle tenemos que obtener la órden que nos dan y posteriormente tenemos que calcular el cocinero que tiene un tiempo menor en ordenes asignado.

Posteriormente, le mandamos al servidor el índice del cocinero a asignar (+1 para que no se mande el cocinero con índice 0, ya que tenemos que asignar un cocinero del 1-10) y sumamos el tiempo de la orden ya procesada al cocinero.

### NOTA

`r.interactive()` tiene un uso clave a la hora de computar este tipo de scripts automaticados ya que nos ahorra mucho tiempo de analizar lógicamente el código que queremos del servidor.

## Flag

`UMASS{subst@nd@rd_c00k}`


