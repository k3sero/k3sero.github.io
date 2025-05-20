---
title: Attack of the Pentium 4 - UmassCTF2025
author: Kesero
description: Reto basado en encontrar a una persona en base a una información.
date: 2025-04-22 20:01:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Dificultad - Media, Osint, Osint - Research, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/2.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Posco`

Dificultad: <font color=orange>Media</font>

## Enunciado

"You really want to play Run 3, but your poor Pentium 4 isn't fast enough! You've heard there's a computer shop worthy of thunderous praise in this building, but you need an expert opinion on their services first. If a computer is good enough to work on games, it should be good enough to play them. It’s been rumored that someone who works on games once purchased a computer from here. Can you find their first game?

Flag format: UMASS{name of the game in English}, for example UMASS{Elden Ring}"

## Archivos

En este reto, tenemos el siguiente archivo.

- `image.jpeg` : Contiene la 1º localización

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204).

![image.jpeg](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/image.jpeg)

## Analizando el reto

Tenemos que encontrar el primer juego que desarrolló una persona que compró un ordenador en la tienda que muestra la imagen. La información que podemos extraer del enunciado es la siguiente.

```
Hay tiendas de ordenadores en ese edificio en concreto
Necesitamos una opinión experta en dicha tienda
Si el ordenador es bueno para trabajar con videojuegos, también lo será para jugarlos
Buscamos a alguien que una vez compró de esa tienda un ordenador
```

## Solver

Para comenzar con este reto, tenemos que ir por partes. Primero vamos a encontrar la ubiación exacta de la imagen que tenemos. La imagen muestra un lugar en Tokio, en esta ubicación.

![ubi](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/ubicacion.png)

Si observamos justo en el edificio donde enfocan, podemos observar que dentro de ese edificio, se encuentra una tienda de ordenadores genérica. Dicha tienda alberga unas 4 tiendas distintas llamadas `acharge`, `hercules`, `vspec` y `zeus`.

![pag](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/pagina.png)

![achar](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/acharge.png)
![hercules](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/hercules.png)
![zeus](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/zeus.png)
![vspec](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/vspec.png)

Llegados a este punto tenemos que mirar en las reseñas de cada página, una opinión experta que relacione los conceptos que se hablan en el enunciado. 

Después de muchas búsquedas y reseñas, podemos decir que la opinión experta es la [siguiente](https://pc-zeus.com/example_13.html).

![reseña](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/rese%C3%B1a.png)

![japones](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Osint/Attack%20of%20the%20Pentium%204/img/japones.jpg)

Sabemos que es la que se menciona porque en la propia reseña incluye una mini entrevista, la cual detalla su trabajo.

Si buscamos por la imagen adjunta a la reseña, podemos saber que su nombre es "Shouhei Tsuchiya" además en su [fanpage](https://www.mobygames.com/person/333977/shouhei-tsuchiya/credits/) se listan los juegos a los cuales ha ayudado a desarrollar. En este caso su primera participación en un juego es en 2003 y pertenece al título "Otogi 2: Immortal Warriors"

## Flag

`UMASS{Otogi 2: Immortal Warriors}`