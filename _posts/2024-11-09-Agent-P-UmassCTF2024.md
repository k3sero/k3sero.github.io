---
title: Agent P - UmassCTF2024
author: Kesero
description: Reto Miscelánea basado en la interpretación de una cadena supuestamente codificada.
date: 2024-11-09 12:28:00 +0800
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Dificultad - Fácil, Misc, Otros - Writeups, UmassCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Agent_P/Agent_P.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `unknown`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"Patrick sees secret, he puts it into computer immediately. But can you read the flag?"

## Archivos

En este reto solo tenemos el siguiente archivo.

- `a.txt` : Contiene una cadena de texto.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Agent_P).

## Analizando el código

Si abrimos el archivo `a.txt` podemos ver la siguiente cadena de texto.


    EDCVGT VFRGYHN CFTGB YTRFGBV YTRFGHBV 6TFGVB FGYTRFV XDRFV RTYTGB 4RFV456YTFGN 7UJM 65RDCVB 5RFVYGGB EDCFTGBHU XDRFV TREDFGBVC RFVFGHYHN ERTDFGCVBEDC 3EDC345TFDFB EDCERTDFGCVB 7YUJKIJN


## Solución

La solución es mucho más simple de lo que parece. En este caso se nos pueden ocurrir mil cosas, como por ejemplo que se trata de un `Cifrado César`, algún tipo de `cifrado afín` o que debemos de usar un `análisis de frecuencia` para decodificar la flag. Aunque recordemos que estamos en la categoría Miscelánea.

Además, el enunciado nos dice que Patricio Estrella nos ha arrojado esta cadena de forma instantánea y supuestamente "codificada"

También, si somos observadores y suponiendo que la flag comienza por `umassctf{`, podemos ver que la `s` coincide con dos cadenas `YTRFGBV` `YTRFGHBV` pero, ¿por qué son diferentes si deberían de ser iguales? ¿Qué es esto y cómo lo resolvemos?

Si observamos detenidamente, nos damos cuenta de que esta cadena no tiene ninguna codificación. Simplemente, si seguimos el trazo de la cadena en el teclado, observamos que se van dibujando caracteres como si de un folio se tratase.

Por ejemplo, la cadena `EDCVGT` dibuja en nuestro teclado una `U`, `VFRGYHN` dibuja una `M`, `CFTGB` dibuja una `A` y así sucesivamente, por lo que si seguimos el trazo completo de todas las cadenas obtendremos la flag.

## Flag

`UMASSCTF{PATRICWASHERE}`

