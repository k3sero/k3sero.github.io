---
title: RF Fan - UmassCTF2025
author: Kesero
description: Reto basado en recuperar una señal infraroja a partir de un archivo de señales
date: 2025-04-24 12:30:00 +0000
categories: [Writeups Competiciones Internacionales, Hardware]
tags: [Difícil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan/img/6.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Sanderbeggar`

Dificultad: <font color=red>Difícil</font>

## Enunciado

"I took this recording from my fan remote. It contains 7 binary messages. Demodulate and decode the signal, then submit the message that should come after the 7th in binary. For example if the messages were 00, 11, 00, 11, 00, 11, 00, you would submit UMASS{11}."

## Archivos

Este reto nos da el siguiente archivo.

- `signal.zip` : Contiene el archivo de señales.iq en su interior

Archivos pesados como  `signal.zip` [aquí](https://drive.google.com/drive/folders/1Tej2_FVHD60dMDcY0HE9wycL4RW4mj1f?usp=sharing).

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan).

## Analizando el reto

En este reto, nos dicen que tenemos una captura de señales infrarojas en el fichero `signal.iq` y que tenemos que predecir el octavo mensaje que se enviaría.

## Solver

Este tipo de retos podemos solucionarlos de varías formas.

1. Con herramientas automatizadas como scripts en python para obtener los valores en binario (demodulación automática)

2. De manera manual mediante el espectograma (si es posible realizar la visualización de las señales)

En nuestro caso, Nacho decidió realizar la manera manual y yo la automatizada. (El ganó)

El procedimiento que el siguió fue muy simple:

1. Transformó el archivo `signal.iq` en `signal.wav` con los siguientes comandos.

    ┌──(kesero㉿kali)-[~]
    └─$ sudo apt install sox

    ┌──(kesero㉿kali)-[~]
    └─$ sox -e float -t raw -r 192000 -b 32 -c 2 signal.iq -t wav -e float -b 32 -c 2 -r 192000 signal.wav

2. Con el `signal.wav` creado, utilizó audiacity para visualizar las señales y efectivamente se podían notar claramente los 7 mensajes captados.

![onda_completa](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan/img/onda_completa.png?raw=true)

Si ampliamos cada mensaje, podemos obtener los mensajes individuales y su representación en el espectograma.

![onda_mensaje](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan/img/unico_mensaje.png?raw=true)

3. Una vez que tenemos la representación, podemos intuir que los picos altos equivalen al bit 1 y la ausencia de picos al bit 0. De esta manera reconstruimos la secuencia infraroja de cada mensaje.
Realizando este procedimiento en los 7 mensajes, obtenemos las siguientes cadenas.

![cadenas](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan/img/Sin%20t%C3%ADtulo.png?raw=true)

```
01010001001111111011100000110010
01010001001111111011100001000101
01010001001111111011100001010100
01010001001111111011100001100111
01010001001111111011100001110110
01010001001111111011100000000001
01010001001111111011100000010000
```

Si analizamos las cadenas podemos segmentaras en varios elementos

```
0101000100111111101110000 011 0 010
0101000100111111101110000 100 0 101
0101000100111111101110000 101 0 100
0101000100111111101110000 110 0 111
0101000100111111101110000 111 0 110
0101000100111111101110000 000 0 001
0101000100111111101110000 001 0 000
```
1. La primera cadena larga corresponde a el identificador del dispositivo. Cada dispositivo infrarojo incluye una etiqueta a modo de identificador de la señal.

2. Los siguientes 3 bits representan el número del mensaje a indicar. Podemos observar como incrementa en 1 bit por cada mensaje y volviendo a 0 cuando existe acarreo.

3. El cuarto bit corresonde a un bit en blanco.

4. La última parte corresponde a una asociación directa de bits a los bits de la sección 2, como si fuese una tabla.

Por tanto lo que nos piden en el ejercicio es predecir el octavo mensaje que se enviaría, para ello lo crearemos por partes:

1. El identificador es igual en cada mensaje

2. El siguiente mensaje tendrá `010` al ser secuancial.

3. El siguiente bit estará a 0

4. Tenemos que encontrar la asociación de `010` que resulta en los bits `011`

Por tanto, la cadena final es la siguiente.

```
0101000100111111101110000 010 0 011
```

## Flag
`UMASS{01010001001111111011100000100011}`