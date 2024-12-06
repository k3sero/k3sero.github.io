---
title: Tracking The Beast - SpookyCTF2024
author: Kesero
description: Reto Cripto basado en Curvas Elipticas.
date: 2024-10-27 22:54:00 +0800
categories: [Writeups Competiciones Internacionales, Cripto]
tags: [Curvas Elípticas, Points, Multiplicativo, Subgrupos, Guessy, Writeups, Difícil]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/Tracking_The_Beast.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `thatoganGuy`

Dificultad: <font color=red>Difícil</font>

## Enunciado

NICC is hot on the trail of bigfoot! He has been following a path equivalent to the curve y^2 = x^3 + 73x + 42 mod 251. Each point along this curve represents one of Bigfoot's hideouts. NICC dicovered in his cave located at (26,38), many references to Green Lantern comics. A large depiction of Green Lantern with 13 rings on his fingers was drawn on the cave wall. I think this is the cover to an old issue of Green Lantern, could something about the issue point to how many more hideouts Bigfoot will travel through before stopping again?


## Archivos

En este reto no nos dan ningún archivo, solamente el enunciado.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best)

## Analizando el Enunciado

Básicamente el enunciado nos dice que están investigando los escondites de Bigfoot a lo largo de la curva elíptica descrita por la ecuación \( y^2 = x^3 + 73x + 42 \) módulo 251.

Además se ha encontrado una de sus cuevas en el punto (26, 38) donde dentro hay referencias a cómics de Green Lantern, incluida una representación de Green Lantern con 13 anillos en los dedos. 

Para obtener la flag, tenemos que encontrar el próximo escondite de Bigfoot, ¿podremos encontrarlo?

## Solución

Básicamente, en este reto nos piden calcular el siguiente punto de la curva donde el Bigfoot puede estar. Para comenzar podemos ver los próximos puntos donde el Bigfoot puede estar, para ello utilizaré la herramienta online [Elliptic Curves over Finite Fields](https://graui.de/code/elliptic2/)

Pero antes de comenzar, vamos a desglosar todos los datos que tenemos.

1. Tenemos la curva elíptica \( y^2 = x^3 + 73x + 42 mod 251\), donde p = 251, a = 73 y b = 42
2. Además tenemos un punto P (26, 38) dentro de la curva.
3. Por último, tenemos una pista (un tanto guessy) la cual nos dice que en la cueva donde se encontró El Bigfoot, hay una referencia de una portada de cómic protagonizada por Linterna Verde con 13 anillos en los dedos.

Antes de continuar desarrollando la pista, vamos a observar los posibles puntos en los que puede estar escondido Bigfoot.

![Grafica](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/Grafica.png?raw=true)
![Subgrupos](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/Subgrupos.png?raw=true)

Es importante saber que elegimos subgrupos dentro del punto P ya que las curvas elípticas tienen estructuras algebraicas que permiten la definición de grupos de puntos. Estos grupos tienen subgrupos que son útiles para realizar operaciones y cálculos específicos. La clave en este reto viene dada por encontrar dichos puntos a lo largo de la curva. Como sabemos que para seguir el camino tenemos un punto inicial P, simplemente tenemos que multiplicar el punto inicial P por un escalar N.

Dicho escalar N lo obtenemos mediante la tercera pista, por lo que tenemos que encontrar la portada a la que se refieren en el enunciado, para ello un poco de OSINT y encontramos lo [siguiente.](https://www.reddit.com/r/comicbooks/comments/a6prip/green_lantern_49_cover_art_by_darryl_banks/)

![Portada](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/Spookyctf2024/Tracking_The_Best/portada.png?raw=true)

Como podemos observar, dicha portada del cómic se corresonde con lo descrito en el enunciado, ¿y ahora que hacemos?

Pues básicamente tenemos que tomar el número 49 equivalente a el número de tomo del cómic como escalar N y operar en la curva elíptica para obtener el punto multiplicativo. N x P

Realizando un breve script en `sage` obtenemos la flag.

```python
F = GF(251)
E = EllipticCurve(F, [73, 42])

P = E.point([26,38])

print(49*P)
```
Ejecutando el código anterior obtenemos el punto del siguiente escondite del Bigfoot el cual se corresponde con (72, 17) y como podemos observar dicho punto existe dentro de la lista.

## Flag

`NICC{72,17}`