---
title: Nuevas Raíces - HackademicsForum2025
author: Kesero
description: Reto OSINT basado en búsqueda de información en la página de HackademicsForum.
date: 2025-04-06 18:00:00 +0000
categories: [Writeups Competiciones Nacionales, Osint]
tags: [Búsqueda, Writeups, Fácil]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Nuevas_Raices/img/5.png?raw=true
  lqip: 
  alt: 
comments: true
---

Nombre del reto: `Nuevas Raíces`

Autor del reto: `kesero`

Dificultad: <font color=orange>Medio</font>

## Enunciado

"Un recién llegado a la administración ha estado perdiendo el tiempo modificando imágenes en la página oficial del Hackademics Forums en lugar de preparar los retos que faltan.
Justo después de terminar su reto, mencionó algo sobre "Aquí comienza la Nueva Era" y "El año cero". Desde entonces, no hemos sabido nada más sobre él.
Tal vez solo sea un lunático vociferando o quizás sus palabras tengan algún significado. Quién sabe..."

## Solución

Para comenzar con el reto, tendremos que visitar la página de [Hackademics Forum](https://hackademics-forum.com/) y una vez dentro, tendremos que jugar a ser Sherlock Holmes.

![1](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Nuevas_Raices/img/1.png?raw=true)

Una vez dentro, para obtener la flag deberemos de irnos a la sección `Quiénes somos`.

![2](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Nuevas_Raices/img/2.png?raw=true)

Posteriormente nos iremos al subapartado `Aprender haciendo`, donde se encuentran imágenes de charlas anteriores.

![3](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Nuevas_Raices/img/3.png?raw=true)

Por último, si analizamos las imágenes de dichas charlas, podemos encontrar que varias de ellas se encuentran modificadas. En una de ellas se visualiza un código QR.


![4](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Nuevas_Raices/img/4.png?raw=true)


![5](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Nuevas_Raices/img/5_a.jpg?raw=true)

Escaneando dicho codigo QR, obtenemos la flag.

![6](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Nuevas_Raices/img/6.png?raw=true)


## Flag

`hfctf{4s1_c0m3nz0_H4ck4d3m1cs_F0rUm}`