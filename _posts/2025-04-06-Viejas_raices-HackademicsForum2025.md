---
title: Viejas Raíces - HackademicsForum2025
author: Kesero
description: Reto OSINT basado en búsqueda de una charla del Aula de Ciberseguridad y Redes.
date: 2025-04-06 15:00:00 +0000
categories: [Writeups Competiciones Nacionales, Osint]
tags: [Búsqueda, Writeups, Fácil]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Viejas_Raices/img/6.png?raw=true
  lqip: 
  alt: 
comments: true
---


Nombre del reto: `Viejas Raíces`

Autor del reto: `kesero`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"El sábado pasado, entre risas, salió el tema de cómo habíamos comenzado en ciberseguridad. Nos sorprendió descubrir que varios de nosotros habíamos dado nuestros primeros pasos gracias a una charla del Aula de Ciberseguridad y Redes.

Intentamos recordar los detalles y coincidimos en que la charla trataba sobre "hackear una máquina". Mañana hemos quedado para resolverla como en aquellos tiempos, pero hay un problema y es que ninguno de nosotros se acuerda del nombre de la máquina...

¿Me echarías una mano encontrando el nombre?"


## Solución

Este ejercicio es un mero calentamiento de la categoría Osint.
Simplemente con realizar una búsqueda en Google con "Aula de Ciberseguridad y Redes", tendremos acceso a la página oficial de la que se hace referencia.


![1](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Viejas_Raices/img/1.png?raw=true)

Dentro de la página podemos ver varios recursos, lo más destado es que se encuentran todas las charlas listadas como artículos en el panel principal.

![2](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Viejas_Raices/img/2.png?raw=true)


Si seguimos scrolleando podemos observar que podemos presionar el botón "Artículos antiguos".

![3](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Viejas_Raices/img/3.png?raw=true)


Listando todas las charlas presentes, llegaremos a la que hace referencia el ejercicio "Hackeando Nuestra primera máquina".

![4](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Viejas_Raices/img/4.png?raw=true)

Clickeando en dicha charla tendremos una descripción a la misma y se listará el nombre de la máquina a la que se hace mención en el enunciado.


![5](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Viejas_Raices/img/5.png?raw=true)

![6](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Viejas_Raices/img/6_a.png?raw=true)


### Opcional

Otro método más sencillo es desplegar el menú "Cursos" y se nos abrirá un menú con las charlas organizadas por años.

![optional](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Nacionales_Writeups/2025/HackademicsForum2025/Osint/Viejas_Raices/img/optional.png?raw=true)


# Flags Válidas

`hfctf{dr4g0nb4ll}`
`hfctf{Dr4g0n-b4ll}`
`hfctf{Dragon Ball}`
`hfctf{Dr4g0n-b4ll.zip}`