---
title: Códigos en python sobre la implementación del Hash MD5
author: Kesero
description: Códigos realizados en python sobre la implementación de MD5.
date: 2024-12-09 18:00:00 +0800
categories: [Criptografía, Códigos en python]
tags: [MD5, Hashing]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Md5/img/Titulo.png?raw=true
  lqip: 
  alt: 
comments: true
---

## Introducción

En este post, contaréis con las prácticas que he desarrollado en `python` sobre MD5, el cual esta implementado a mano y cuenta con diversas funcionalidades añadidas en un `menú MD5` como puede ser el realizar el `hash md5 de texto`, `archivos` ya sean imágenes o archivos en texto claro y por último cuenta con la `búsqueda de posibles colisiones` de hashes en MD5.

En comparación con prácticas anteriores, esta no ha hecho uso de una relación de ejercicios, simplemente era una práctica opcional de la asignatura y es por ello que simplemente teníamos que hacer una implementación simple de `MD5` en python.

Es por ello que comparto con vosotros todos los códigos desarrollados para que le echéis un vistazo, además de compartiros los recursos teóricos utilizados con el fin de aprender lo necesario para comprender en su totalidad el funcionamiento de dichos cifrados.

## Recursos Teóricos

En cuanto a teoría respecta, os dejo adjuntada la presentación sobre métodos de hashing y concretamente con la presentación que seguimos para el `hash MD5` para que podáis entender y comprender los procedimientos seguidos.

![MD5](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Teoria/Md5/img/portada.png?raw=true)

Presentación [aquí](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Teoria/Md5/MD5.pdf).


## Ejercicios

Tendréis todos los códigos desarrollados en mi Github, más concretamente [aquí](https://github.com/k3sero/Blog_Content/tree/main/Criptografia/Codigos_Practicas/Md5).

Destacar que en estas prácticas, contamos con un `menuMD5` el cual necesita el resto de ficheros para poder ejecutarse sin problemas.

### Menú Md5

```py
"""
Nombre del archivo: menu_md5.py
Descripción: Este módulo contiene el menú con opciones dedicadas a MD5.
Autor: Carlos Marín Rodríguez
"""

import struct
import math

from md5 import *
from menuFunctions import *

def menu():
    """
    Muestra un menú de opciones para que el usuario seleccione diferentes funcionalidades relacionadas con hashes MD5.
    El menú incluye opciones para calcular el hash de un mensaje, archivo, imagen, o generar colisiones de hashes.
    """

    while True:

        print("\n─────────────────────────────────────────────────")
        print("===================  Menú MD5  ==================")
        print("─────────────────────────────────────────────────\n")
        print("    1. Realizar el hash de un mensaje.")
        print("    2. Realizar el hash de un archivo de texto.")
        print("    3. Realizar el hash de una imagen.")
        print("    4. Realizar colisiones de hashes.")
        print("\n─────────────────────────────────────────────────")
        print("    5. Salir")
        print("─────────────────────────────────────────────────")
        opcion = input("\n[!] Elige una opción: ").strip()

        # Realizar hash de un mensaje.
        if opcion == '1':
            mensaje = str(input("\n[!] Introduce el mensaje a hashear: "))
            hash_md5 = calcular_md5(mensaje)
            print(f"\n[+] El hash MD5 de '{mensaje}' es: {hash_md5}")
        
        # Realizar hash de un archivo.
        elif opcion == '2':
            hash_md5 = hashear_archivos()
            print(f"\n[+] El hash MD5 del archivo del archivo introducido es: {hash_md5}")
        
        # Realizar hash de una imagen.
        elif opcion == '3':
            hash_md5 = hashear_imagen()
            print(f"\n[+] El hash MD5 del archivo de la imagen es: {hash_md5}")
        
        # Colisión de hashes.
        elif opcion == '4':
            colision()
            break
        
        # Salir del programa.
        elif opcion == '5':
            print("\n[!] Saliendo del programa.")
            break

        else:
            print("[!] Opción no válida. Por favor, selecciona una opción del 1 al 4.")

if __name__ == "__main__":
    menu()
```


### Funciones Menú

```py
"""
Nombre del archivo: menu_md5.py
Descripción: Este módulo contiene funciones relacionadas con el menú MD5.
Autor: Carlos Marín Rodríguez
"""

from os import urandom
from hashlib import md5 # Para el hashing de imagenes y colisonado algo más eficiente.
import hashlib
from md5 import *

# Esta función es redundante y se puede simplificar utilizando únicamente hashear_archivos(), pero para separar los prompts, he decidido dejarla en el código.
def hashear_imagen():
    """
    Calcula el hash MD5 de una imagen (archivo) dado.

    Retorno:
    - str
        El hash MD5 del archivo de imagen, expresado como una cadena hexadecimal de 32 caracteres.
    """
    print(f"\n[INFO] La imagen debe de estar en la misma ruta del script.")
    imagen_path = str(input("[!] Introduce el nombre de la imagen a hashear (con su extensión, p.ej. imagen.png): "))
    
    try:
        # Abrimos la imagen en modo binario.
        with open(imagen_path, 'rb') as f:  
            imagen_data = f.read()
            
            # Usamos hashlib para calcular el MD5.
            md5_hash = hashlib.md5(imagen_data).hexdigest()
            return md5_hash

    except Exception as e:
        print(f"[!] Error al calcular el hash de la imagen: {e}")
        return None

def hashear_archivos():
    """
    Permite al usuario seleccionar un archivo en la misma carpeta para calcular su hash MD5.
    """
    print(f"\n[INFO] El archivo debe de estar en la misma ruta del script.")
    archivo = str(input("[!] Introduce el nombre del archivo a hashear (con su extensión, p.ej. ejemplo.txt): "))
    try:
        with open(archivo, 'rb') as f:
            contenido = f.read().decode("latin-1")

        hash_md5 = calcular_md5(contenido)
        return hash_md5

    except FileNotFoundError:
        print(f"[!] El archivo '{archivo}' no existe.")
    except Exception as e:
        print(f"[!] Error al procesar el archivo: {e}")

def colision():
    """
    Realiza la búsqueda de una colisión de un hash MD5, comparando los primeros n dígitos entre un hash dado y
    hashes generados aleatoriamente. Este método demuestra el concepto de colisiones en hashes, pero es
    computacionalmente ineficiente para valores grandes de n.

    El usuario puede especificar cuántos dígitos iniciales del hash deben coincidir (n). 
    Se recomienda usar valores pequeños para n (menores a 7) para observar resultados prácticos en un tiempo razonable.

    NOTA: Este enfoque utiliza números aleatorios generados por `os.urandom` para buscar colisiones, 
    y no está diseñado para aplicaciones prácticas donde se requiera eficiencia.
    """

    print("──────────────────────────────────────────────────────────────────────────────────────────────────")
    print(f"\n[INFO] La colisión de un hash completo requiere mucho poder de cómputo y tiempo.")
    print(f"[INFO] Este método es funcional pero computacionalmente muy poco eficiente.")
    print(f"\n[INFO] Es por ello que puedes realizar colisión de los n primeros digitos del hash.")
    print(f"[INFO] Puedes introducir n = 32 si quieres la colisión del hash completa, pero no es nada recomendable.")
    print(f"\n[INFO] Para observar el funcionamiento, recomiendo fijar un n menor a 7 .")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────")

    hash = str(input("\n[!] Introduce el hash a colisionar: "))
    n = int(input("[!] Introduce el número de digitos a colisonar: "))

    while(True):

        colision = urandom(32)
        
        # Utilizar md5 de hashlib, para un cómputo más eficiente.
        colision_hash = md5(colision).hexdigest()

        if colision_hash[:n] == hash[:n]:
            print("\n[+] Colisión encontrada!")
            print(f"[+] Hash original es: {hash}")
            print(f"[+] Hash encontrado:  {colision_hash}")
            print(f"[+] Hash pertenece a la palabra: {colision.decode("latin-1")}")
            print(f"[+] Hash encontrado (Bytes): {colision}")
```

# Implementación básica MD5 (sin librerías)

```py
"""
Nombre del archivo: md5.py
Descripción: Este módulo contiene la funcionalidad de crear hashes en MD5 a partir de mensajes.
Autor: Carlos Marín Rodríguez
"""

import struct
import math

def rotar_izquierda(x, n):
    """
    Realiza una rotación circular hacia la izquierda de n bits.

    Parámetros:
    - x: int
        El número entero sobre el cual se realizará la rotación. Se asume que este número está representado 
        en un formato de 32 bits (un número entre 0 y 2^32 - 1).
    - n: int
        El número de bits a rotar hacia la izquierda. Este valor debe estar en el rango de 0 a 31, ya que se 
        trata de una rotación en un entero de 32 bits.

    Retorno:
    - int
        El número resultante después de la rotación circular hacia la izquierda de x por n bits. La operación
        se realiza de manera que se mantenga el valor dentro del rango de 32 bits (0 a 2^32 - 1).
    """

    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def preparar_mensaje(mensaje):
    """
    Prepara el mensaje para cumplir con el formato requerido en el algoritmo.
    
    Parámetros:
    - mensaje: str
        El mensaje que se desea preparar, que se espera como una cadena de texto.

    Retorno:
    - bytes
        El mensaje preparado en formato de bytes, con los bits añadidos y la longitud del mensaje original.
    """

    mensaje_bytes = mensaje.encode('latin-1')  # Convertir el mensaje en bytes
    longitud_original = len(mensaje_bytes) * 8  # Longitud del mensaje en bits

    # Añadir un bit '1' seguido de ceros.
    mensaje_bytes += b'\x80'  # Añadir un 1 (en binario: 10000000)
    while (len(mensaje_bytes) * 8) % 512 != 448:
        mensaje_bytes += b'\x00'

    # Añadir la longitud original del mensaje como un entero de 64 bits.
    mensaje_bytes += struct.pack('<Q', longitud_original)  # '<Q': Little-endian, entero de 64 bits
    return mensaje_bytes

def funciones_f_g_h_i(x, y, z, i):
    """
    Selecciona y aplica la función correspondiente (F, G, H, I) según la ronda actual en el proceso de hash.
    Cada una de estas funciones opera sobre tres entradas (x, y, z) y devuelve un valor basado en una operación lógica entre ellas. 

    Parámetros:
    - x: int
        El primer valor de entrada para las funciones F, G, H o I. 
    - y: int
        El segundo valor de entrada para las funciones F, G, H o I. 
    - z: int
        El tercer valor de entrada para las funciones F, G, H o I. 
    - i: int
        El índice de la ronda actual. Dependiendo de este valor, se seleccionará una de las funciones.

    Retorno:
    - int
        El resultado de aplicar la función correspondiente a los valores de entrada `x`, `y` y `z`.
    """

    if i < 16:
        return (x & y) | (~x & z)
    elif i < 32:
        return (x & z) | (y & ~z)
    elif i < 48:
        return x ^ y ^ z
    else:
        return y ^ (x | ~z)

def constante_t(i):
    """
    Calcula la constante T(i) como el entero de 32 bits de |sin(i+1)| * 2^32.

    Parámetros:
    - i: int
        El índice de la ronda actual, generalmente de 0 a 63.

    Retorno:
    - int
        La constante T(i) calculada como un entero de 32 bits, resultado de |sin(i + 1)| * 2^32,
        restringido a 32 bits mediante un AND con 0xFFFFFFFF.
    """

    return int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF

def calcular_md5(mensaje):
    """
    Calcula el hash MD5 de un mensaje dado.

    Parámetros:
    - mensaje: str
        El mensaje (o texto) para el cual se desea calcular el hash MD5.

    Retorno:
    - str
        El hash MD5 del mensaje, expresado como una cadena hexadecimal de 32 caracteres.
    """
    # Preparamos el mensaje.
    mensaje_preparado = preparar_mensaje(mensaje)

    # Valores iniciales.
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    # Constantes de rotación aplicadas a cada uno de los 64 pasos de cada bloque de 512.
    rotaciones = [
        7, 12, 17, 22,  # Ronda 1 (i < 16)
        5, 9, 14, 20,   # Ronda 2 (i < 32)
        4, 11, 16, 23,  # Ronda 3 (i < 48)
        6, 10, 15, 21   # Ronda 4 (i < 64)
    ]

    # Procesamos cada bloque de 512 bits.
    for i in range(0, len(mensaje_preparado), 64):

        bloque = mensaje_preparado[i:i+64]

        # Dividimos el bloque en 16 palabras de 32 bits.
        M = list(struct.unpack('<16I', bloque))  
        
        # Inicializamos los valores para este bloque.
        a, b, c, d = A, B, C, D

        # Realizamos las 64 iteraciones.
        for j in range(64):

            if j < 16:
                k = j
                s = rotaciones[j % 4]

            elif j < 32:
                k = (5 * j + 1) % 16
                s = rotaciones[4 + (j % 4)]

            elif j < 48:
                k = (3 * j + 5) % 16
                s = rotaciones[8 + (j % 4)]

            else:
                k = (7 * j) % 16
                s = rotaciones[12 + (j % 4)]

            f = funciones_f_g_h_i(b, c, d, j)
            temp = (a + f + M[k] + constante_t(j)) & 0xFFFFFFFF
            a, b, c, d = d, (b + rotar_izquierda(temp, s)) & 0xFFFFFFFF, b, c

        # Actualizamos los valores iniciales.
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    # Combinamos los resultados en el hash final.
    result = ''.join(f'{x:02x}' for x in struct.pack('<4I', A, B, C, D))
    
    return result

'''
# Testing. Ejemplo.
mensaje = "jonatan"
print(f"[+] El mensaje es: {mensaje}")

hash_md5 = calcular_md5(mensaje)
print(f"\n[!] El hash MD5 de '{mensaje}' es: {hash_md5}")
'''
```