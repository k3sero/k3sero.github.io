---
title: Códigos en python sobre métodos Esteganográficos
author: Kesero
description: Códigos realizados en python sobre LSB y métodos de ordenación de imágenes.
date: 2024-12-09 17:25:00 +0800
categories: [Cripto, Códigos en python]
tags: [Cripto, Cripto - Códigos en python, Estego - LSB ]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/Titulo.png
  lqip: 
  alt: 
comments: true
---

## Introducción

En este post, contaréis con las prácticas que he desarrollado en `python` sobre métodos esteganográficos los cuales permiten ocultar cadenas de texto mediante `LSB` (Bit menos significativo), junto a el método de desordenar y ordenar imágenes para revelar posibles imágenes ocultas.

Dichas prácticas se han desarrollado a partir de la relación de ejercicios impuestas por el profesor con el fin de guiar la implementación de cada función.

Es por ello que comparto con vosotros todos los códigos desarrollados para que le echéis un vistazo, además de compartiros los recursos teóricos utilizados con el fin de aprender lo necesario para comprender en su totalidad el funcionamiento de dichos cifrados.

## Recursos Teóricos

En cuanto a teoría respecta, os dejo adjuntada la presentación sobre dichos métodos esteganográficos para que podáis entender y comprender los procedimientos seguidos.

![Estego](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Teoria/Esteganografia/img/portada.png)

Presentación [aquí](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Teoria/Esteganografia/Esteganografia.pdf).


## Relación de ejercicios

La relación de ejercicios utilizada para la realización de las prácticas es la siguiente.

![Relacion_1](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/Practica_Esteganografia-1.png)


## Ejercicios

Tendréis todos los códigos desarrollados en mi Github, más concretamente [aquí](https://github.com/k3sero/Blog_Content/tree/main/Criptografia/Codigos_Practicas/Esteganografia).

Destacar que en estas prácticas, no tenemos un menú interactivo para comprobar las funcionalidades de manera dinámica. Es por ello que he adjuntado a cada ejercicio una prueba de `Testing` la cual se puede modificar a gusto del usuario para comprobar cada funcionalidad.

## Método LSB

### Ejercicio 1 (Cargar Imágenes)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex1.png)

```py
"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

from PIL import Image
import numpy as np

def img2grayscalematrix(image_path):
    """
    Convierte una imagen a escala de grises y la devuelve como una matriz 2D.
    
    Parámetros:
        image_path (str): Ruta del archivo de imagen.
    
    Retorna:
        numpy.ndarray: Matriz 2D de la imagen en escala de grises.
    """

    # Cargar la imagen
    image = Image.open(image_path).convert("L")
    
    # Convertir la imagen a escala de grises
    grayscale_image = image.convert("L")
    
    # Obtener los datos de la imagen en escala de grises y convertirla en una matriz NumPy.
    grayscale_matrix = np.array(grayscale_image)
    
    return grayscale_matrix

def img2rgbmatrix(image_path):
    """
    Convierte una imagen a RGB y la devuelve como una matriz 3D.
    
    Parámetros:
        image_path (str): Ruta del archivo de imagen.
    
    Retorna:
        numpy.ndarray: Matriz 3D de la imagen en formato RGB.
    """
    # Cargar la imagen
    image = Image.open(image_path)
    
    # Convertir la imagen a RGB
    rgb_image = image.convert("RGB")
    
    # Obtener los datos de la imagen en formato RGB y convertirla en una matriz NumPy
    rgb_matrix = np.array(rgb_image)
    
    return rgb_matrix

'''
# Testing. Ejemplos
image_path = "imagen.png"
    
# Obtener la matriz en escala de grises
grayscale_matrix = img2grayscalematrix(image_path)
print("[!] Matriz de la imagen en escala de grises:\n")
print(grayscale_matrix)
    
# Obtener la matriz en RGB
rgb_matrix = img2grayscalematrix(image_path)
print("\n[!] Matriz de la imagen en RGB:\n")
print(rgb_matrix)
'''
```

### Ejercicio 2 (Conversión Bit-Texto)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex2.png)

```py
"""
Nombre del archivo: ex2.py
Descripción: Este módulo contiene la funciones del ejercicio 2.
Autor: Carlos Marín Rodríguez
"""

def text2bits(text):
    """
    Convierte un texto a su representación en bits (ASCII).
    
    Parámetros:
        text (str): El texto que se quiere convertir a bits.
    
    Retorna:
        str: Representación en bits del texto.
    """

    # Convertir cada carácter del texto a su valor ASCII, luego a binario de 8 bits
    bits = ''.join(format(ord(c), '08b') for c in text)
    return bits

def bits2text(bits):
    """
    Convierte una cadena de bits a su texto original.
    
    Parámetros:
        bits (str): La cadena de bits que se quiere convertir a texto.
    
    Retorna:
        str: El texto correspondiente a los bits.
    """

    # Dividir la cadena de bits en grupos de 8 (un byte por carácter)
    text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
    return text

'''
# Testing. Ejemplos.
text = "Hello world" 
print(f"[!] El texto a convertir es: {text}")
# Convertir texto a bits.
bits = text2bits(text)
print(f"\n[!] Texto a Bits: {bits}")
    
# Convertir los bits de vuelta a texto.
recovered_text = bits2text(bits)
print(f"\n[!] Bits a Texto: {recovered_text}")
'''
```


### Ejercicio 3 (Cifrado/Descifrado por LSB)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex3.png)

```py
"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3.
Autor: Carlos Marín Rodríguez
"""

from PIL import Image
from ex2 import *

def LSBsimplecypher(image_input, text, output_image):
    """
    Oculta un mensaje en los primeros píxeles de una imagen utilizando el método de Least Significant Bit (LSB).

    Parámetros:
        image_path (str): Ruta de la imagen original en blanco y negro en la que se desea ocultar el mensaje.
        text (str): El mensaje que se quiere ocultar. Este mensaje se convierte a su representación en bits (ASCII).
        output_image (str): Ruta donde se guardará la imagen con el mensaje oculto.

    Retorna:
        None: La función guarda la imagen con el mensaje oculto en el archivo especificado por `output_image`.

    """
    # Convertir el mensaje a bits.
    bits = text2bits(text)
    msg_len = len(bits)
    
    # Abrir la imagen
    img = Image.open(image_input).convert('L')
    pixels = list(img.getdata())
    
    # Comprobamos si hay suficiente espacio.
    if msg_len > len(pixels):
        raise ValueError("\n[!] No hay espacio en la imagen para ocultar el mensaje.")
    
    new_pixels = []

    # Iterar sobre los píxeles y su índice.
    for i, pixel in enumerate(pixels):

        if i < msg_len:

            # Modificar el bit menos significativo del píxel.
            modified_pixel = (pixel & ~1) | int(bits[i])
            new_pixels.append(modified_pixel)
        else:
            # Si no se necesita modificar, conservamos el píxel original.
            new_pixels.append(pixel)
    
    # Guardamos la imagen resultante.
    img.putdata(new_pixels)
    img.save(output_image)

    print(f"\n[+] Mensaje oculto en {output_image}")

def LSBsimpledecypher(image_input, secret_len):
    """
    Extrae un mensaje oculto en los primeros píxeles de una imagen en blanco y negro utilizando el método de Least Significant Bit (LSB).
    
    Parámetros:
        image_input (str): Ruta de la imagen de entrada que contiene el mensaje oculto en los primeros píxeles.
        secret_len (int): Longitud del mensaje oculto (en número de bits), que debe coincidir con la cantidad de píxeles modificados en la imagen.

    Retorna:
        str: El mensaje oculto extraído de la imagen, convertido de vuelta a texto.
    """

    # Abrimos la imagen.
    img = Image.open(image_input).convert('L')
    pixels = list(img.getdata())
    
    # Extraemos los bits menos significativos.
    bits = ''.join(str(pixel & 1) for pixel in pixels[:secret_len])
    
    return bits2text(bits)

'''
# Testing. Ejemplo.
secret = "Hola mundo"
secret_len = len(text2bits(secret))

image_input = 'imagen.png'
image_output = 'imagen_codificada.png'

# Incrustar el mensaje.
LSBsimplecypher(image_input, secret, image_output)

# Obtención del mensaje.
secret_recovered = LSBsimpledecypher(image_output, secret_len)

print(f"\n[+] Mensaje recuperado: {secret_recovered} ")
'''
```


### Ejercicio 4 (Cifrado/Descifrado por LSB Complejo)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex4.png)

```py
"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funciones del ejercicio 4.
Autor: Carlos Marín Rodríguez
"""
from PIL import Image
from ex2 import * 

def LSBcomplexcypher(image_path, text, output_image, s):
    """
    Oculta un mensaje en una imagen en blanco y negro utilizando un salto de s píxeles.
    
    Parámetros:
        image_path (str): Ruta de la imagen original en blanco y negro en la que se desea ocultar el mensaje.
        text (str): El mensaje que se quiere ocultar. Este mensaje se convierte a su representación en bits (ASCII).
        output_image (str): Ruta donde se guardará la imagen con el mensaje oculto.
        s (int): El salto de píxeles para ocultar cada bit del mensaje (por ejemplo, 3 para saltar 3 píxeles entre cada bit).
        
    Excepciones:
        ValueError: Si la imagen no tiene suficiente espacio para ocultar el mensaje con el salto s.
    
    Retorna:
        None: La función guarda la imagen con el mensaje oculto en el archivo especificado por output_image.
    """
    
    # Convertimos el mensaje a bits.
    bits = text2bits(text)
    msg_len = len(bits)
    
    # Abrir la imagen y convertirla a escala de grises.
    img = Image.open(image_path).convert('L')
    pixels = list(img.getdata()) 
    
    # Comprobar si la imagen tiene suficiente espacio para ocultar el mensaje con el salto s.
    if s * msg_len > len(pixels):
        raise ValueError("\n[!] No hay suficiente espacio en la imagen para ocultar el mensaje con el salto de píxeles dado.")
    
    # Copiamos los píxeles originales para modificar solo los necesarios.
    new_pixels = pixels.copy()  
    
    # Iterar sobre los bits del mensaje y colocarlos en los píxeles correspondientes (con salto de s).
    for i, bit in enumerate(bits):
        pixel_index = (i + 1) * s - 1  # Índice del píxel donde se colocará el bit.
        new_pixels[pixel_index] = (new_pixels[pixel_index] & ~1) | int(bit)  # Modificar el LSB.
    
    # Colocamos los nuevos píxeles en la imagen y la guardamos.
    img.putdata(new_pixels)
    img.save(output_image)

    print(f"\n[+] Mensaje oculto en {output_image}")


def LSBcomplexdecypher(image_input, secret_len, s):
    """
    Extrae un mensaje oculto en una imagen en blanco y negro utilizando un salto de s píxeles.

    Parámetros:
        image_input (str): Ruta de la imagen de entrada que contiene el mensaje oculto en los píxeles con salto de s.
        secret_len (int): Longitud del mensaje oculto (en número de bits), que debe coincidir con la cantidad de píxeles modificados en la imagen.
        s (int): El salto de píxeles para extraer cada bit del mensaje.
        
    Retorna:
        str: El mensaje oculto extraído de la imagen, convertido de vuelta a texto.
    
    Excepciones:
        ValueError: Si la longitud del mensaje (secret_len) es mayor que el número de píxeles modificados en la imagen.
    """

    # Abrimos la imagen y la convertimos a escala de grises (blanco y negro).
    img = Image.open(image_input).convert('L')
    pixels = list(img.getdata())
    
    # Verificar si la longitud del mensaje es válida (que no exceda el número de píxeles disponibles).
    if secret_len > len(pixels) // s:
        raise ValueError("\n[!] La longitud del mensaje es mayor que el número de píxeles modificados en la imagen.")
    
    # Extraer los bits menos significativos (LSB) de los píxeles con salto de s.
    bits = ''.join(str(pixels[(i + 1) * s - 1] & 1) for i in range(secret_len))
    
    # Convertir los bits extraídos de nuevo a texto.
    return bits2text(bits)

'''
# Testing. Ejemplos
# Incrustar el mensaje.
input_image = "imagen.png"
output_image = "imagen_codificada.png"
s = 89 # Salto de pixeles.

secret = "Est3 e5 Un M3ns4j3 4lt4m43nte Secret0!"
print(f"[!] Este es el mensaje a ocultar: {secret}")
secret_len = len(text2bits(secret))

LSBcomplexcypher(input_image, secret, output_image, s)

# Recuperar el mensaje.
secret_message = LSBcomplexdecypher(output_image, secret_len, s)
print("\n[+] Mensaje recuperado:", secret_message)
'''
```

## Desordenado de Imágenes

### Ejercicio 1 (Función invertible)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex_2_1.png)

```py
"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

def algeucl(a,b):
    """
    Calcula el Máximo Común Divisor (GCD) de dos números utilizando el algoritmo de Euclides. (P. anterior)

    El algoritmo de Euclides es un método eficiente para encontrar el GCD de dos números enteros.
    La función realiza iteraciones para calcular el residuo de la división de los dos números hasta llegar al GCD.

    Parámetros:
        a : int
            El primer número entero para calcular el GCD.
        
        b : int
            El segundo número entero para calcular el GCD.

    Retorna:
        int
            El Máximo Común Divisor (GCD) de los dos números proporcionados.
    """

    # Comprobacion de errores (Enteros,0 y negativos).
    if not isinstance(a, int) or not isinstance(b, int):
        raise ValueError("[!] Los números deben ser enteros.")
    if a == 0 and b == 0:
        raise ValueError("[!] El GCD de 0 y 0 no está definido.")
    if a < 0 or b < 0:
        print("[W] Uno de los dos números es negativo. Se procdederá con el cálculo.")

    while b > 0:
        
        module = a % b
        a = b
        b = module

    return a

def isinvertible(matrix, n):
    """
    Determina si una matriz 2x2 es invertible en el conjunto Zn.
    
    Parámetros:
        matrix (list of lists): Matriz 2x2 representada como una lista de listas [[a, b], [c, d]].
        n (int): El módulo en el cual determinar la invertibilidad de la matriz.
        
    Retorna:
        bool: True si la matriz es invertible en Zn, False en caso contrario.
    """

    # Extraer los elementos de la matriz 2x2.
    a, b = matrix[0]
    c, d = matrix[1]
    
    # Calcular el determinante de la matriz.
    determinant = (a * d - b * c) % n
    
    # Verificar si el determinante es coprimo con n.
    if algeucl(determinant, n) == 1:
        return True
    else:
        return False

'''
# Testing. Matriz de ejemplo.
matrix = [[1, 2], [3, 4]]
print("[+] La matriz es:")
print(matrix)

# Determinar si la matriz es invertible en Z5
n = 5
print(f"\n[+] Vamos a invertir la matriz en Z{n}")

print(isinvertible(matrix, n))  # Salida: True, ya que el determinante (1*4 - 2*3) = -2 ≡ 3 (mod 5), y gcd(3, 5) = 1.

# Matriz de ejemplo con otro módulo
matrix = [[1, 2], [2, 4]]
print("\n[+] La matriz es:")
print(matrix)

# Determinar si la matriz es invertible en Z6
n = 6
print(f"\n[+] Vamos a invertir la matriz en Z{n}")

print(isinvertible(matrix, n))  # Salida: False, ya que el determinante (1*4 - 2*2) = 0, y gcd(0, 6) = 6.
'''
```


### Ejercicio 2 (Inversa de potencias)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex_2_2.png)

```py
"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

import numpy as np

def powinverse(A, n):
    """
    Determina el menor p tal que A^p = I (mod n) en Zn.
    
    Parámetros:
    - A (numpy.ndarray): Una matriz cuadrada de enteros que representa la matriz A.
    - n (int): El valor del módulo en el anillo Zn (números enteros módulo n).
    
    Retorna:
    - int: El menor valor de p tal que A^p ≡ I (mod n), donde I es la matriz identidad, o
           None si no se encuentra tal p dentro de un número razonable de iteraciones.
    """

    # Matriz identidad.
    identity = np.eye(A.shape[0], dtype=int) % n

    # Inicializamos la potencia de A para futuras iteraciones.
    power = np.eye(A.shape[0], dtype=int) % n
    
    # Límite de iteraciones.
    max_iterations = n ** 2  

    for p in range(1, max_iterations + 1):

        # Calculamos A^p mod n
        power = np.dot(power, A) % n
        
        # Comparación de la igualdad
        if np.array_equal(power, identity):
            return p

    print("\n[!] No se encontró un p tal que A^p = I en Zn.")
    return 

'''
# Testing. Ejemplo.
A = np.array([[0, 1], [1, 0]]) 
n = 10

p = powinverse(A, n)
print("[+] El valor de p es:", p)
'''
```


### Ejercicio 3 (Función Desordena/Ordena Imágen)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex_2_3.png)

```py
"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3.
Autor: Carlos Marín Rodríguez
"""

import numpy as np
from PIL import Image

def es_invertible_mod(A, n):
    """
    Verifica si una matriz 2x2 es invertible en el espacio modular Zn.

    Parámetros:
    - A: np.ndarray
        Matriz cuadrada (2x2) cuyas entradas son enteros.
    - n: int
        Módulo Zn en el que se desea verificar la invertibilidad.

    Retorno:
    - bool
        `True` si la matriz es invertible en Zn.
        `False` si no es invertible en Zn.
    """

    # Calculamos el determinante de A
    det = int(round(np.linalg.det(A)))
    det_mod = det % n
    try:
        # Intentamos calcular el inverso modular
        inv_det = pow(det_mod, -1, n)
        return True
    except ValueError:
        return False

def inversa_mod(A, n):
    """
    Calcula la inversa de una matriz 2x2 en el espacio modular Zn.
    
    Parámetros:
    - A: np.ndarray
        Matriz cuadrada (2x2) cuyas entradas son enteros.
    - n: int
        Módulo Zn en el que se desea calcular la inversa.

    Retorno:
    - np.ndarray
        Matriz inversa de A en Zn. Si no existe una inversa, se generará una excepción.
    """

    # Calculamos determinante de A.
    det = int(round(np.linalg.det(A)))
    det_mod = det % n

    # Calculamos el inverso modular del determinante modular.
    inv_det = pow(det_mod, -1, n)

    # Matriz adjunta escalada
    adj = np.round(np.linalg.inv(A) * det).astype(int)  
    
    # Multiplicamos por el inverso modular y aplicamos módulo
    return (inv_det * adj) % n  

def desordenaimagen(A, imagen, n):
    """
    Desordena una imagen aplicando la transformación definida por la matriz A en el espacio modular Zn.
    
    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en el espacio modular Zn. Se utiliza para calcular las nuevas coordenadas
        de los píxeles.
    - imagen: np.ndarray o PIL.Image.Image
        Imagen que se desea desordenar. Puede ser en escala de grises o a color (RGB), en formato NumPy
        o como objeto de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito Zn.

    Retorno:
    - imagen_desordenada: np.ndarray
        Imagen desordenada en formato NumPy con las mismas dimensiones que la imagen original.
    """

    if not es_invertible_mod(A, n):
        raise ValueError("\n[!] La matriz A no es invertible en Z{}".format(n))
    
    print(f"\n[+] Desordenando la imagen...")

    # Convertir imagen a formato NumPy. (si es necesario)
    if isinstance(imagen, Image.Image):
        imagen = np.array(imagen)

    filas, columnas = imagen.shape[:2]
    imagen_desordenada = np.zeros_like(imagen)
    
    for i in range(filas):
        for j in range(columnas):

            # Calculamos las nuevas coordenadas
            nueva_pos = np.dot(A, [i, j]) % n
            nueva_i, nueva_j = nueva_pos

            # Mapeamos los píxeles. (Asegurándonos de que estén dentro de los límites)
            nueva_i %= filas
            nueva_j %= columnas
            imagen_desordenada[nueva_i, nueva_j] = imagen[i, j]
    
    return imagen_desordenada

def ordenaimagen(A, imagen_desordenada, n):
    """
    Restaura la imagen original desordenada usando la matriz A y su inversa en el espacio modular Zn.
    
    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en el espacio modular Zn. Se utiliza para calcular las coordenadas originales
        de los píxeles.
    - imagen_desordenada: np.ndarray o PIL.Image.Image
        Imagen desordenada que se desea restaurar. Puede estar en formato NumPy (array) o como un objeto
        de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito Zn.

    Retorno:
    - imagen_restaurada: np.ndarray
        Imagen restaurada en formato NumPy con las mismas dimensiones que la imagen original.
    """
    
    # Calculamos la inversa.
    A_inv = inversa_mod(A, n)

    print(f"\n[+] Ordenando la imagen...")

    # Convertir imagen a formato NumPy si es necesario
    if isinstance(imagen_desordenada, Image.Image):
        imagen_desordenada = np.array(imagen_desordenada)

    # Inicializamos las dimensiones y la imagen_restaurada.
    filas, columnas = imagen_desordenada.shape[:2]
    imagen_restaurada = np.zeros_like(imagen_desordenada)
    
    for i in range(filas):
        for j in range(columnas):
            # Calculamos las nuevas coordenadas
            nueva_pos = np.dot(A_inv, [i, j]) % n
            nueva_i, nueva_j = nueva_pos
            # Mapeamos los píxeles de vuelta
            nueva_i %= filas
            nueva_j %= columnas
            imagen_restaurada[nueva_i, nueva_j] = imagen_desordenada[i, j]
    
    return imagen_restaurada

'''
# Testing. Ejemplo.
original_image = "imagen.png"
shuffle_image = "imagen_desordenada.png"
ordered_image = "imagen_ordenada.png"

# Matriz de desorden.
A = np.array([[1, 5], [2, 3]])

# Cargar una imagen.
imagen = Image.open(original_image).convert("RGB")
imagen_np = np.array(imagen)

# Obtenemos las dimensiones.
ancho, alto = imagen.size

# Desordenamos la imagen y la guardamos. (Como es cuadrada, utilizamos una dimensión cualquiera)
imagen_desordenada = desordenaimagen(A, imagen_np, ancho)
imagen_desordenada_pil = Image.fromarray(imagen_desordenada)

imagen_desordenada_pil.save(shuffle_image)  
print(f"[+] Imagen desordenada guardada en {shuffle_image}")

# Leer la imagen desordenada para reordenar.
imagen_desordenada_cargada = np.array(Image.open(shuffle_image))

# Restaurar la imagen original. (Realmente, podemos utilizar de nuevo la funcion de desordena (añadir calculo inversa A), ya que al desordenar una imagen desordenada, obtenemos la imagen original)
imagen_restaurada = ordenaimagen(A, imagen_desordenada_cargada, ancho)
imagen_restaurada_pil = Image.fromarray(imagen_restaurada)

imagen_restaurada_pil.save(ordered_image)  
print(f"[+] Imagen ordenada guardada en {ordered_image}")
'''
```


### Ejercicio 4 (Función Desordena/Ordena Imágen con K)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex_2_4.png)

```py
"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funciones del ejercicio 4.
Autor: Carlos Marín Rodríguez
"""

import numpy as np
from PIL import Image
from ex3 import * 

def desordenaimagenite(A, imagen, n, k):
    """
    Desordena una imagen aplicando la transformación definida por  A^k  en el espacio modular  Zn.
    Solicita al usuario un valor k adecuado para calcular A^k.
    
    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en el espacio modular Zn.
    - imagen: np.ndarray o PIL.Image.Image
        Imagen que se desea desordenar. Puede ser en escala de grises o a color (RGB), en formato NumPy
        o como objeto de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito  Zn .
    - k: int
        Escalar para obtener A^k.

    Retorno:
    - imagen_desordenada: np.ndarray
        Imagen desordenada en formato NumPy con las mismas dimensiones que la imagen original.
    """

    # Pedimos el valor de k al usuario.
    while True:
        try:
            # Comprobamos el k introducido.
            if k <= 0:
                raise ValueError("[!] k debe ser un entero positivo.")
            # Calculamos  A^k .
            A_k = np.linalg.matrix_power(A, k) % n
            if not es_invertible_mod(A_k, n):
                raise ValueError("[!] La matriz A^k no es invertible en Z{} para el valor de k={}.".format(n, k))
            break
        except ValueError as e:
            print(e)
    
    print(f"\n[+] Usando A^k con k={k}:")
    print(f"[+] Matriz utilizada: ")
    print(A_k)

    print(f"\n[+] Desordenando la imagen...")

    # Convertir imagen a formato NumPy si es necesario.
    if isinstance(imagen, Image.Image):
        imagen = np.array(imagen)

    filas, columnas = imagen.shape[:2]
    imagen_desordenada = np.zeros_like(imagen)
    
    # Desordenamos la imagen usando  A^k.
    for i in range(filas):
        for j in range(columnas):

            nueva_pos = np.dot(A_k, [i, j]) % n
            nueva_i, nueva_j = nueva_pos
            nueva_i %= filas
            nueva_j %= columnas
            imagen_desordenada[nueva_i, nueva_j] = imagen[i, j]
    
    return imagen_desordenada

def ordenaimagenite(A, imagen_desordenada, n, k):
    """
    Restaura la imagen original desordenada usando A^k y su inversa en el espacio modular Zn.
    Solicita al usuario el mismo valor k que se utilizó para desordenar.

    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en el espacio modular Zn.
    - imagen_desordenada: np.ndarray o PIL.Image.Image
        Imagen desordenada que se desea restaurar. Puede estar en formato NumPy (array) o como un objeto
        de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito Zn.
    - k: int
        Escalar para obtener A^k.

    Retorno:
    - imagen_restaurada: np.ndarray
        Imagen restaurada en formato NumPy con las mismas dimensiones que la imagen original.
    """
    
    # Pedimos el valor de k al usuario.
    while True:
        try:
            # Comprobamos el valor de k.
            if k <= 0:
                raise ValueError("[!] k debe ser un entero positivo.")

            # Calculamos  A^k  e invertimos la matriz.
            A_k = np.linalg.matrix_power(A, k) % n
            if not es_invertible_mod(A_k, n):
                raise ValueError("[!] La matriz A^k no es invertible en Z{} para el valor de k={}.".format(n, k))
            
            # Calculamos la inversa.
            A_k_inv = inversa_mod(A_k, n)
            break

        except ValueError as e:
            print(e)
    
    print(f"[+] Usando la inversa de A^k con k={k}:")
    print(f"[+] Matriz utilizada:")
    print(A_k_inv)

    print(f"\n[+] Restaurando la imagen...")

    # Convertir imagen a formato NumPy si es necesario.
    if isinstance(imagen_desordenada, Image.Image):
        imagen_desordenada = np.array(imagen_desordenada)

    # Obtenemos las dimensiones e inicializamos la imagen_restaurada.
    filas, columnas = imagen_desordenada.shape[:2]
    imagen_restaurada = np.zeros_like(imagen_desordenada)
    
    # Restauramos la imagen usando la inversa de A^k.
    for i in range(filas):
        for j in range(columnas):

            nueva_pos = np.dot(A_k_inv, [i, j]) % n
            nueva_i, nueva_j = nueva_pos
            nueva_i %= filas
            nueva_j %= columnas
            imagen_restaurada[nueva_i, nueva_j] = imagen_desordenada[i, j]
    
    return imagen_restaurada

'''
# Testing. Ejemplo.
# Definimos una matriz A y un módulo n.
original_image = "imagen.png"
shuffle_image = "imagen_desordenada_ite.png"
restored_image = "imagen_restaurada_ite.png"

# Matriz utilizada.
A = np.array([[1, 2], [3, 5]])

# Obtenemos el valor de k.
k = int(input("[!] Introduce un valor de k (entero positivo): "))

# Cargamos la imagen.
imagen = Image.open(original_image).convert("RGB")

# Obtenemos las dimensiones de la imagen.
ancho, alto = imagen.size


# Desordenamos la imagen.
imagen_desordenada = desordenaimagenite(A, imagen, ancho, k)
Image.fromarray(imagen_desordenada).save(shuffle_image)
print(f"[+] La imagen se desordenó correctamente.")

# Restauramos la imagen.
k = int(input("\n[!] Introduce el valor de k utilizado en la desordenación para ordenar la imagen: "))
imagen_restaurada = ordenaimagenite(A, imagen_desordenada, ancho, k)
Image.fromarray(imagen_restaurada).save(restored_image)
print(f"[+] La imagen se restauró correctamente.")
'''
```


### Ejercicio 5 (Iteración de K en Desordena/Ordena Imágen)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/Esteganografia/img/ex_2_5.png)

```py
"""
Nombre del archivo: ex5.py
Descripción: Este módulo contiene la funciones del ejercicio 5.
Autor: Carlos Marín Rodríguez
"""

import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from ex3 import *
from ex4 import *
from ex5 import *

def desordenaimagenproceso(A, imagen, n, max_k):
    """
    Desordena la imagen de manera iterativa usando la matriz A^k en Zn, mostrando cómo cambia la imagen
    a medida que aumentamos el valor de k.
    
    Parámetros:
    - A: np.ndarray
        Matriz 2x2 invertible en Zn. Se utiliza para calcular las nuevas coordenadas de los píxeles.
    - imagen: np.ndarray o PIL.Image.Image
        Imagen que se desea desordenar. Puede ser en escala de grises o RGB, en formato NumPy o como objeto de la librería PIL.
    - n: int
        Módulo en el que se trabaja para garantizar que las coordenadas estén dentro del espacio finito Zn.
    - max_k: int
        Número máximo de iteraciones (valores de k) para aplicar. Default es 5.
        
    Retorno:
    - None
    """

    # Convertir imagen a formato NumPy. (si es necesario)
    if isinstance(imagen, Image.Image):
        imagen = np.array(imagen)

    # Crear la figura para mostrar las imágenes.
    plt.figure(figsize=(12, 8))

    # Iterar para aplicar la transformación A^k de 1 a max_k.
    for k in range(1, max_k + 1):

        # Calculamos A^k.
        A_k = np.linalg.matrix_power(A, k) % n
        
        # Desordenamos la imagen con A^k.
        imagen_desordenada = desordenaimagenite(A, imagen, n, k)
        
        # Mostrar la imagen desordenada.
        plt.subplot(1, max_k, k)
        plt.imshow(imagen_desordenada)
        plt.title(f'k = {k}')
        plt.axis('off')  # Desactivar los ejes para mejor visualización

        # Guardamos las imágenes intermedias.
        imagen_desordenada_pil = Image.fromarray(imagen_desordenada)
        imagen_desordenada_pil.save(f"imagen_desordenada_k_{k}.png")

    print(f"\n[!] Para salir de la representación, presione Ctrl + c.")

    plt.tight_layout()
    plt.show()

'''
# Testing. Ejemplo.
original_image = "imagen.png"

# Cargamos la imagen.
imagen = Image.open(original_image).convert("RGB")
imagen_np = np.array(imagen)

# Obtenemos las dimensiones de la imagen.
ancho, alto = imagen.size

# Matriz de desorden.
A = np.array([[1, 2], [3, 5]])

max_k = 5
print(f"[+] Calcularemos el desorden desde k = 1 hasta k = {max_k}")
# Llamamos a la función para mostrar el proceso de desorden con valores de k de 1 a 5.
desordenaimagenproceso(A, imagen_np, ancho, max_k)
'''
```