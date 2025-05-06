---
title: Beauty - HackademicsForum2024
author: Kesero
description: Reto de Esteganografía basado en la extracción de bytes alternos en canales RGB.
date: 2024-11-09 15:42:00 +0800
categories: [Writeups Competiciones Nacionales, Esteganografía N]
tags: [Dificultad - Media, Estego, Estego - RGB, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2024/Estego/HackademicsForumCTF2024/Beauty/BeautyT.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Daysapro`

Dificultad: <font color=orange>Media</font>

## Enunciado

"La belleza es como un lienzo en blanco, esperando ser pintado con las perspectivas de cada mirada. Es un eco cambiante, único para cada alma, que se revela en la diversidad de nuestros corazones y mentes. En estas formas subjetivas, se esconde un mensaje objetivo, listo para ser descubierto."

## Archivos

En este reto, tenemos los siguientes archivos.

- `challenge.py` : Contiene el código fuente principal.
- `original.png` : Imagen original.
- `beauty.png` : Imagen alterada.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Nacionales_Writeups/2024/Estego/HackademicsForumCTF2024/Beauty).


## Analizando el código

Si abrimos la imagen `original.png` y la imagen `beauty.png`, podemos observar que ambas son "iguales"

![original](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2024/Estego/HackademicsForumCTF2024/Beauty/original.png)

Además, el código fuente es el siguiente.


```py
from PIL import Image


original_image = Image.open("original.png")
new_image = Image.new("RGB", (original_image.size[0], original_image.size[1]))
size = original_image.size[0] * original_image.size[1]

original_matrix = original_image.load()
new_matrix = new_image.load()

for i in range(0, new_image.size[0]):
    for j in range(0, new_image.size[1]):
        new_matrix[i, j] = original_matrix[i, j]


bin_flag = ''.join(format(byte, '08b') for byte in open("flag.txt", "rb").read())

a = 0
b = 1
c = 1

for bit in bin_flag:
    position = ((a % size) // new_image.size[0], (a % size) % new_image.size[1])
    new_matrix[position[0], position[1]] = (original_matrix[position[0], position[1]][0], original_matrix[position[0], position[1]][1], original_matrix[position[0], position[1]][2] + int(bit))
    a = b
    b = c
    c = a + b


new_image.save("beauty.png")
original_image.close()
new_image.close()
```

## Solución

En el código de `challenge.py` básicamente lo que esta haciendo es a partir de la imagen `original.png` incrusta un mensaje en binario a determinados píxeles de la imágen, concretamente en la componente azul del canal `RGB` siguiendo la sucesión de `fibonacci` a la hora de elegir dichos píxeles a alterar.

De forma mucho más detallada y línea por línea, el código hace lo siguiente.

1. Importamos la clase `Image` del módulo `PIL`, que es una biblioteca de Python utilizada para manipular imágenes. 
2. Abrimos la imagen llamada `original.png` en una variable.
3. Creamos una nueva imagen vacía con el mismo tamaño que la imagen original, utilizando el modo "RGB" (rojo, verde, azul).
4. Calcula el tamaño total de la imagen original multiplicando su ancho por su altura y lo almacenamos en `size`.
5. Cargamos las matrices de píxeles de las imágenes original y new en las variable `original_matrix` y `new_matrix`, básicamente nos sirve como accesos directos eficientes para manipular los píxeles de las imágenes.
6. En el bucle, copiamos cada píxel de la imagen original a la nueva imagen, iterando sobre `i` y `j` de la nueva asignando los valores correspondientes.
7. Leemos el archivo en binario de `flag.txt` y lo convertimos cada byte en una cadena binaria de 8 bits. Estas cadenas se concatenan en una sola cadena y se asigna a la variable `bin_flag`.
8. Inicializamos los valores `a`, `b` y `c` correspondientes a la sucesión de fibonacci.
9. Inicializamos un bucle por cada bit de `bin_flag`.

    - 9.1 Calcula una posición gracias a la componente `a` de la sucesión de fibonacci junto con el tamaño y el módulo para asegurar que dicha posición pertenece a la imagen.
    - 9.2 Modifica el valor del componente azul del píxel en la posicion calculada previamente sumándole el valor del bit. Esto modifica la imagen nueva basándose en los bits del archivo `flag.txt`.
    - 9.3 Recalculamos los valores de la sucesión de fibonacci.

10. Guardamos la imagen modificada en el archivo `beauty.png`.
11. Cerramos los archivos de la imagen original y la nueva para liberar recursos.


A partir de este punto tenemos claro lo que tenemos que hacer, calcular las posiciones nuevamente siguiendo la misma sucesión de fibonacci, extraer dicho valor del canal azul de la imagen `beauty.png` y por último comparamos dicho valor con el valor de la imagen `original.png`. Si ambos valores son iguales entonces quiere decir que el bit resultante es un 0; si ambos valores son distintos entonces quiere decir que el bit resultante es un 1, ya que ha habido modificación en la imagen `beauty.png` ¿Sencillo verdad?

Pues este es el script final.



```py
from PIL import Image

def bits_a_ascii(bits):
    bloques = [bits[i:i+8] for i in range(0, len(bits), 8)]
    
    caracteres = [chr(int(bloque, 2)) for bloque in bloques]
    
    cadena_ascii = ''.join(caracteres)
    
    return cadena_ascii

original_image = Image.open("original.png")
beauty_image = Image.open("beauty.png")
original_matrix = original_image.load()
beauty_matrix = beauty_image.load()

new_image = Image.new("RGB", (original_image.size[0], original_image.size[1]))

size = original_image.size[0] * original_image.size[1]

a = 0
b = 1
c = 1
chain_result = ""
position = (0,0)

for i in range (0, 30*8):

    position = ((a % size) // new_image.size[0], (a % size) % new_image.size[1])
    original_pixel = (original_matrix[position[0], (position[1])][2])
    beauty_pixel = (beauty_matrix[(position[0]), position[1]][2])

    if original_pixel != beauty_pixel:

        bit_result = 1
    else: 
        bit_result = 0

    chain_result += str(bit_result) 

    a = b
    b = c
    c = a + b

print("Esta es la flag en binario:", chain_result)
print("Esta es la flag en ascii: ", bits_a_ascii(chain_result))


original_image.close()
beauty_image.close()
```

La salida del programa es la siguiente.

    Esta es la flag en binario: 011010000110011001100011011101000100011001111011011001100011000101100010010011110110111001100001010000010110001100010001010001110100000101110000010100100011010100110011001000100011010001011111001000110101001101110000001100000100111100111101
    Esta es la flag en ascii:  hfctF{f1bOnaAcGApR53"4_#Sp0O=

Espera, ¿Lo tenemos? ¿O no?

Hay 2 problemas que tiene todo esto que no estamos teniendo en cuenta.

1. En principio acordamos que habia un problema dado a que no estamos teniendo en cuenta que hay colisión de posiciones dentro de la imagen, es decir, hay posiciones de píxeles en la imagen que se modifican más de una vez, machacando bits en el proceso. Esto ocurre debido a el poco tamaño de los módulos utilizados para calcular `positions` junto a todas las iteraciones que se realizan. Recordemos que por cada caracter de la flag se recorren 8 veces el bucle.

Para comprobar si se repiten las posiciones, simplemente sumamos en una lista todas las posiciones y con la función `Counter()` de `collections`, contamos las veces que se repiten cada par de datos y si se repiten más de 1 vez significa que hay colisión.

```py
from collections import Counter
def repeated_positions(list):

    contador = Counter(list)

    print("Pares que se repiten:")
    for par, repeticiones in contador.items():
        if repeticiones > 1:
            print(f"{par}: {repeticiones} veces")
```
Para nuestra sorpresa, podemos comprobar que NO hay posiciones repetidas más allá del inicio. Por lo tanto podemos descartar completamente este problema.

    Pares que se repiten:
    (0, 1): 2 veces
    Estas son las posiciones que se repiten y machacan: None

2. Si concretamente, el bit de la flag a sumar cae en una posición donde la componente azul del pixel es 255, dicho bit no pasaría a ser 256 ni 0, simplemente se quedaria en el mismo valor 255.

Por tanto tenemos que refinar a un más el código para contemplar estos casos especiales y establecer una "x" en dicho bit conflictivo para posteriormente procesarlo manualmente.

Con las modificaciones mencionadas, el código sería el siguiente.

```py
from PIL import Image

def bits_a_ascii(bits):
    bloques = [bits[i:i+8] for i in range(0, len(bits), 8)]
    
    caracteres = [chr(int(bloque, 2)) for bloque in bloques]
    
    cadena_ascii = ''.join(caracteres)
    
    return cadena_ascii

original_image = Image.open("original.png")
beauty_image = Image.open("beauty.png")
original_matrix = original_image.load()
beauty_matrix = beauty_image.load()

new_image = Image.new("RGB", (original_image.size[0], original_image.size[1]))

size = original_image.size[0] * original_image.size[1]

a = 0
b = 1
c = 1
chain_result = ""
position = (0,0)
cont = 1

for i in range (0, 30*8):

    position = ((a % size) // new_image.size[0], (a % size) % new_image.size[1])
    original_pixel = (original_matrix[position[0], (position[1])][2])
    beauty_pixel = (beauty_matrix[(position[0]), position[1]][2])

    if original_pixel != beauty_pixel:

        bit_result = 1
    elif beauty_pixel == 255: 
        bit_result = "x"
    else: 
        bit_result = 0

    if cont % 8 == 0:
        bit_result =str(bit_result) + " "

    chain_result += str(bit_result) 

    a = b
    b = c
    c = a + b
    cont += 1

print("Esta es la flag en binario:", chain_result)

original_image.close()
beauty_image.close()
```

La salida de dicho programa es la siguiente.

    01101000 01100110 01100011 01110100 01x00110 x1111011 01100110 001100x1 01100010 01x01111 011x1110 011x0001 010000x1 01100011 00x10001 010xx111 x1000001 01110000 0101001x 0x110101 00110011 0x100010 0011010x 01011111 0x1x0011 01x10011 01110x00 00110000 x1x01111 0x111101

Llegados a este punto es sencillo, simplemente tenemos que interpretar manualmente si el caracter es un 0 o un 1 para ello vamos probando valores y los vamos ainterpretando a carácteres `ASCII`.

    01101000 --> h
    01100110 --> f
    01100011 --> c
    01110100 --> t
    01x00110 --> F o f
    x1111011 --> û o {
    01100110 --> f
    001100x1 --> 3 o 1
    01100010 --> b 
    01x01111 --> O o o
    011x1110 --> n o ~
    011x0001 --> q o a
    010000x1 --> A o C
    01100011 --> c
    00x10001 --> 1 o 
    010xx111 --> G, O, W, _ (Respectivamente)
    x1000001 --> Á o A
    01110000 --> p
    0101001x --> R o S
    0x110101 --> u o 5
    00110011 --> 3
    0x100010 --> b o "
    0011010x --> 4 o 5
    01011111 --> _
    0x1x0011 --> #, 3, c, s (Respectivamente)
    01x10011 --> S o s
    01110x00 --> p o t
    00110000 --> 0
    x1x01111 --> O, o, Ï, ï (Respectivamente)
    0x111101 --> = o }

Sabiendo como es el formato de la flag, podemos ir concatenando resultados, solamente tendriamos dudas en los caracteres que sean mayúscula y minúscula entre otros.

    hfctf{f1b(O,o)na(A,C)c1_Apru3b4_3(S,s)t0(O,o)}

A partir de estra reconstrucción generamos todas las posibles combinaciones y alguna de ellas será la correcta.

    hfctf{f1b(O,o)na(A,C)c1_Apru3b4_3(S,s)t0(O,o)}
    
    hfctf{f1bOnaAc1_Apru3b4_3St0O}
    hfctf{f1bOnaAc1_Apru3b4_3St0o}
    hfctf{f1bOnaAc1_Apru3b4_3st0O}
    hfctf{f1bOnaAc1_Apru3b4_3st0o}
    hfctf{f1bOnaCc1_Apru3b4_3St0O}
    hfctf{f1bOnaCc1_Apru3b4_3St0o}
    hfctf{f1bOnaCc1_Apru3b4_3st0O}
    hfctf{f1bOnaCc1_Apru3b4_3st0o}

    hfctf{f1bonaAc1_Apru3b4_3St0O}
    hfctf{f1bonaAc1_Apru3b4_3St0o}
    hfctf{f1bonaAc1_Apru3b4_3st0O}
    hfctf{f1bonaAc1_Apru3b4_3st0o}
    hfctf{f1bonaCc1_Apru3b4_3St0O}
    hfctf{f1bonaCc1_Apru3b4_3St0o}
    hfctf{f1bonaCc1_Apru3b4_3st0O}
    hfctf{f1bonaCc1_Apru3b4_3st0o}
    
Probando estas posibles combinaciones, al final una de ellas sería la correcta.

## Flag

`hfctf{f1bOnaCc1_ApRu3b4_3st0o}`