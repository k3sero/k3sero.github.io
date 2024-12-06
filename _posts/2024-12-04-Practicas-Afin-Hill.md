---
title: Codigos para Afin y Hill - 1337UP LIVE CTF2024
author: Kesero
description: Códigos realizados en python para el cifrado Afín y cifrado Hill.
date: 2024-12-04 20:42:00 +0800
categories: [Cripografía, Códigos en python]
tags: [Afin, Hill, Códigos]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Afin_Hill/Titulo.png?raw=true
  lqip: 
  alt: 
comments: true
---

## Introducción

En este post, contaréis con las prácticas que he desarrollado en `python` sobre el cifrado Afín y el cifrado Hill. Dichas prácticas se han desarrollado a partir de la relación de ejercicios impuestas por el profesor con el fin de guiar la implementación de cada función.

Es por ello que comparto con vosotros todos los códigos desarrollados para que le echéis un vistazo, además de compartiros los recursos teóricos utilizados con el fin de aprender lo necesario para comprender en su totalidad el funcionamiento de dichos cifrados.

## Relación de ejercicios

La relación de ejercicios utilizada para la realización de las prácticas es la siguiente.

![Relacion](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Afin_Hill/Pr%C3%A1ctica_Afin.png?raw=true)

### Ejercicios

Tendréis todos los códigos desarrollados en mi Github, más concretamente [aquí](https://github.com/k3sero/Blog_Content/tree/main/Criptografia/Codigos_Practicas/Afin_Hill).

Os compartiré el menú desglosado de cada cifrado pero dichos menús requieren de funciones establecidas en los ejercicios anteriores `ex1` y `ex2`, es por ello que necesitaréis todos los códigos si queréis ejecutarlos en local.

### Menú Afín

```py
"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3 y el menú para Afín.
Autor: Carlos Marín Rodríguez
"""

from ex1 import *
from ex2 import *

def Afincypher(text, k, d):
    """
    Cifra un texto usando el cifrado Afín: f(x) = k*x + d (mod 26).

    El cifrado Afín mapea cada letra del texto a una nueva letra mediante 
    la fórmula f(x) = k*x + d, donde 'k' es la clave de multiplicación 
    y 'd' es el desplazamiento.

    Parámetros:
        text : str
            Texto a cifrar, que puede contener letras y espacios.
        k : int
            Clave multiplicativa que debe ser coprima con 26.
        d : int
            Clave de desplazamiento.

    Retorna:
        str
            Texto cifrado en base al cifrado Afín.
    
    Excepciones:
        ValueError
            Si 'k' no es coprimo con 26, lo que hace que el cifrado no sea válido.
    """

    n = 26
    list = []
    ciphertext = ""

    # Comprobamos la coprimalidad.
    if algeucl(k, n) != 1:
        raise ValueError("\n[!] El valor de k no es válido. Deber se coprimo con 26.")

    list = TexttoNumber(text)

    for item in list:

        # Aunque no se pide, de esta manera manejamos los espacios (espacio --> -1).
        if item == -1:
            ciphertext += ' '
            continue
        
        y = (k * item + d) % n
        ciphertext += chr(y + ord('A')) 

    return ciphertext

def Afindecypher(ciphertext, k, d):
    """
    Descifra un texto cifrado utilizando el cifrado Afín: x = k^-1 * (y - d) (mod 26).

    Esta función invierte el proceso del cifrado Afín usando la fórmula de descifrado:
    x = k^-1 * (y - d) mod n, donde 'k^-1' es el inverso modular de 'k' en Z26.

    Parámetros:

        ciphertext : str
            Texto cifrado a descifrar, que puede contener letras y espacios.
        k : int
            Clave utilizada en el cifrado, debe ser coprima con 26.
        d : int
            Clave de desplazamiento utilizada en el cifrado.

    Retorna:

        str
            Texto descifrado.
    """

    n = 26
    plaintext = ""

    # Comprobamos nuevamente la coprimalidad de k y n.
    if algeucl(k, n) != 1:
        raise ValueError("\n[!] El valor de k no es válido. Debe ser coprimo con n.")

    k_inv = invmod(k, n)
    cipher_numbers = TexttoNumber(ciphertext)

    for num in cipher_numbers:

        if num == -1:
            plaintext += ' '
            continue
        
        # Aplicamos la fórmula de descifrado: x = k^-1 * (y - d) mod n.
        x = (k_inv * (num -d)) % n
        plaintext += chr(x + ord('A'))

    return plaintext 

def guesskd(y,x):
    """
    Calcula los posibles valores de k (clave multiplicativa) y d (desplazamiento) 
    en el cifrado Afín, dados un carácter cifrado y su correspondiente carácter del texto llano.

    La fórmula utilizada es: y = k * x + d (mod 26), donde y es el carácter cifrado 
    y x es el carácter del texto llano. La función genera todos los posibles pares 
    de k y d que cumplen esta ecuación.

    Parámetros:

        y : str
            Carácter cifrado (texto cifrado).
        x : str
            Carácter del texto llano correspondiente.

    Retorna:

        list[tuple[int, int]]
            Lista de tuplas con los posibles valores de k (clave multiplicativa) 
            y d (desplazamiento) que cumplen la ecuación de cifrado Afín.
    """

    n = 26 

    # Convertimos los caracteres en valores numéricos.
    y_num = TexttoNumber(y)[0]
    x_num = TexttoNumber(x)[0]

    possible_kd = []

    # Iteramos sobre posibles valores de k.
    for k in range(1, n):

        # Comprobamos si k es coprimo con n.
        if algeucl(k, n) == 1:

            # Calculamos d usando la fórmula: d = (y - k * x) mod n
            d = (y_num - k * x_num) % n
            possible_kd.append((k, d))

    return possible_kd

def opcion1():
    """
    Función que cifra un texto mediante el cifrado Afín utilizando un valor de k 
    (clave multiplicativa) y un valor de d (desplazamiento) dados por el usuario.

    Esta función solicita al usuario el texto llano, el valor de k y el valor de d, 
    y luego cifra el texto utilizando el cifrado Afín: f(x) = (k * x + d) mod 26.

    Parámetros:
        Ninguno (los parámetros se obtienen del usuario a través de entradas).

    Retorna:
        Ninguno (imprime el texto cifrado en consola).
    """

    text = input("\n[!] Introduce el texto llano: ")
    k = int(input("[!] Introduce el valor de k (debe ser coprimo con 26, Ej: 25): "))
    d = int(input("[!] Introduce el valor de d (Ej: 3): "))

    if algeucl(k, 26) != 1:
        print("\n[!] El valor de k no es válido. Debe ser coprimo con 26.")
    else:
        ciphertext = Afincypher(text, k, d)
        print(f"\n[+] Texto cifrado: {ciphertext}")


def opcion2():
    """
    Función que descifra un texto cifrado utilizando el cifrado Afín. El usuario puede elegir entre dos opciones:
    1. Descifrar el texto en base a un valor de k (clave multiplicativa) y d (desplazamiento) conocidos.
    2. Descifrar el texto utilizando un enfoque de fuerza bruta, probando todas las combinaciones posibles de k y d.

    Parámetros:
        Ninguno (los parámetros se obtienen del usuario a través de entradas).

    Retorna:
        Ninguno (imprime el texto descifrado o las opciones posibles en consola).
    """

    ciphertext = input("\n[!] Introduce el texto cifrado: ").upper()

    print("\n────────────────────────────────────────────────\n")
    print("  1. Descifrar en base a k y d conocido.")
    print("  2. Descifrar el texto mediante fuerza bruta")
    print("\n────────────────────────────────────────────────")
    print("  3. Atrás")
    print("────────────────────────────────────────────────\n")
    op = input("\n[!] Elige una opción: ").strip()

    try:
        # Opción 1: Descifrar en base a k y d conocido.
        if op == '1':

            k = int(input("\n[!] Introduce el valor de k utilizado anteriormente: "))
            d = int(input("[!] Introduce el valor de d utilizado anteriormente: "))

            if algeucl(k, 26) != 1:
                print("\n[!] El valor de k no es válido. Debe ser coprimo con 26.")
            else:
                plaintext = Afindecypher(ciphertext, k, d)
                print(f"\n[+] Texto descifrado: {plaintext}")

        # Opción 2: Descfirar mediante fuerza bruta.
        if op == '2':

            it = 0
            y = input("\n[!] Introduce la letra del texto cifrada: ").upper()
            x = input("[!] Introduce una posible letra en texto claro correspondiente: ").upper()

            if len(y) != 1 or len(x) != 1 or not y.isalpha() or not x.isalpha():
                print("\n[!] Debes introducir un único carácter alfabético para cada letra.")
            else:
                kd_values = guesskd(y, x)
                print("\n[+] Estos son los posibles textos en claro:\n")
                for k, d in kd_values:
                    it += 1
                    print(f"[Texto {it}]  {Afindecypher(ciphertext, k, d)}")

        # Opción 3: Atrás.
        if op == '3':
            return

    except ValueError as ve:
        print(f"\n[!] Error de entrada: {ve}")
    except Exception as e:
        print(f"\n[!] Ha ocurrido un error: {e}")

def Afincriptoanalisis():
    """
    Función interactiva para realizar un criptoanálisis del cifrado Afín. Permite al usuario:
    1. Cifrar un texto en base a un valor de k y d.
    2. Descifrar un texto a partir de un texto cifrado, usando claves conocidas o mediante fuerza bruta.
    3. Salir del menú.

    Parámetros:
        Ninguno (se obtiene entrada del usuario durante la ejecución).

    Retorna:
        Ninguno (imprime resultados o mensajes según la elección del usuario).

    Excepciones:
        Si ocurre un error durante la entrada o ejecución de las funciones, se muestra un mensaje de error.
    """

    salir = False

    while not salir:
        print("\n─────────────────────────────────────────────────")
        print("=========  Menú de Criptoanálisis Afín  =========")
        print("─────────────────────────────────────────────────\n")
        print("  1. Cifrar texto en base a un k y d")
        print("  2. Descifrar texto a partir del texto cifrado")
        print("\n─────────────────────────────────────────────────")
        print("  3. Salir")
        print("─────────────────────────────────────────────────")
        opcion = input("\n[!] Elige una opción: ").strip()

        try:
            # Opción 1: Cifrar texto.
            if opcion == '1':
                opcion1()
                
            # Opción 2: Descifrar texto.
            elif opcion == '2':
                opcion2()
  
            # Opción 3: Salir.
            elif opcion == '3':
                salir = True
                print("\n[!] Saliendo del menú...")
                return

            else:
                # Opción no válida.
                print("\n[!] Opción no válida. Por favor, intente de nuevo.")

        except ValueError as ve:
            print(f"\n[!] Error de entrada: {ve}")
        except Exception as e:
            print(f"\n[!] Ha ocurrido un error: {e}")

        print()  # \n.

if __name__ == "__main__":
    Afincriptoanalisis()
```

### Menú Hill

```py
"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funciones para el cifrado Hill.
Autor: Carlos Marín Rodríguez
NOTA: La función de descifrado a veces arroja error de numpy "zero divisor", no he conseguido depurarla corectamente.
"""

from ex1 import *
from ex2 import *
from ex3 import *

import numpy as np
import random
from sympy import Matrix

# Diccionario para el cifrado.
diccionario_encryt = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9, 'K': 10, 'L': 11,
            'M': 12, 'N': 13, 'O': 14, 'P': 15, 'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21, 'W': 22, 'X': 23, 'Y': 24, 'Z': 25}

# Diccionario para el descifrado.
diccionario_decrypt = {'0' : 'A', '1': 'B', '2': 'C', '3': 'D', '4': 'E', '5': 'F', '6': 'G', '7': 'H', '8': 'I', '9': 'J', '10': 'K', '11': 'L', '12': 'M',
            '13': 'N', '14': 'O', '15': 'P', '16': 'Q', '17': 'R', '18': 'S', '19': 'T', '20': 'U', '21': 'V', '22': 'W', '23': 'X', '24': 'Y', '25': 'Z'}

def determinante_modular(matriz, m):
    """
    Calcula el determinante de una matriz bajo un módulo dado.

    Parámetros:
        matriz : numpy.ndarray o list
            La matriz cuadrada (de tamaño n x n) de la cual se desea calcular el determinante.
            Puede ser una lista de listas o un arreglo de numpy.
        m : int
            El módulo bajo el cual se calculará el determinante.

    Retorna:
        int
            El determinante de la matriz calculado bajo el módulo especificado.
    """

    matriz = np.array(matriz)

    # Calculamos el determinante normal
    det = int(np.linalg.det(matriz))  
    return det % m  # Retornamos el determinante módulo m

def ingresarClave(size):
    """
    Solicita al usuario que ingrese una matriz clave para el cifrado Hill.

    Parámetros:
        size : int
            El tamaño de la matriz clave (size x size), donde size es un entero positivo.

    Retorna:
        numpy.ndarray
            Una matriz cuadrada de tamaño size x size con valores en el rango [0, 25].
    """

    print(f"\n[!] Ingrese los elementos de la matriz de clave {size}x{size} fila por fila (valores entre 0 y 25):")
    matriz = []
    for i in range(size):
        fila = input(f"[!] Ingrese la fila {i + 1} (numeros separados por espacios): ").strip().split()
        if len(fila) != size:
            print(f"\n[!] Debe ingresar exactamente {size} números por fila.")
            return None
        try:
            fila = [int(num) for num in fila]
            if any(num < 0 or num > 25 for num in fila):
                print("\n[!] Los valores deben estar entre 0 y 25.")
                return None
            matriz.append(fila)
        except ValueError:
            print("\n[!] Debe ingresar solo números enteros.")
            return None

    # Convertir la lista a numpy.ndarray
    return np.array(matriz)

def hillGenKey(size):
    """
    Función que genera una matriz llave aleatoria para el cifrado Hill, dado un tamaño específico de la matriz.
    La matriz generada es de tamaño size x size, con valores aleatorios en el rango de 0 a 25.
    La matriz generada es válida si su determinante es coprimo con 26 (invertible en módulo 26).
    
    Parámetros:
        size : int
            El tamaño de la matriz cuadrada (n x n) que se generará.
    
    Retorna:
        numpy.ndarray
            Matriz de tamaño size x size con valores aleatorios, que sirve como clave para el cifrado Hill.
    """

    while True:
        # Genera una matriz de valores aleatorios en el rango de 0 a 25.
        matrix = np.random.randint(0, 26, (size, size))

        # Calculamos el determinante de la matriz en módulo 26.
        det_mod_26 = determinante_modular(matrix, 26)

        # Comprobamos si el determinante es coprimo con 26 (es decir, determinante no es 0 y es invertible)
        if det_mod_26 != 0 and algeucl(det_mod_26, 26) == 1:
            return matrix 

def hillCypher(message, key):
    """
    Función que cifra un mensaje utilizando el cifrado Hill.
    Devuelve el texto cifrado en base al mensaje y la clave introducida.

    Parámetros:
        message : str
            El mensaje a cifrar, que debe ser un texto en mayúsculas y puede contener espacios.
            Si el tamaño del mensaje no es múltiplo del tamaño de la matriz clave, se rellenará con la letra 'X'.
        key : numpy.ndarray
            La clave utilizada para el cifrado, debe ser una matriz cuadrada (de tamaño n x n) con valores en el rango [0, 25].

    Retorna:
        str
            El texto cifrado generado usando el cifrado Hill.
    """

    matrix_mensaje = []
    list_temp = []
    cifrado_final = ''
    ciphertext_temp = ''
    ciphertext = ''
    cont = 0

    # Convertir el mensaje a mayusculas.
    message = message.upper()

    # Si el tamaño del mensaje es menor o igual al tamaño de la clave.
    if len(message) <= len(key):

        # Convertir el tamaño del mensaje al tamaño de la clave, si no es igual, se añaden 'X' hasta que sean iguales los tamaños.
        while len(message) < len(key):
            message = message + 'X'

        # Crear la matriz para el mensaje.
        for i in range(0, len(message)):
            matrix_mensaje.append(diccionario_encryt[message[i]])

        # Se crea la matriz
        matrix_mensaje = np.array(matrix_mensaje)

        # Se multiplica la matriz clave por la de mensaje.
        cifrado = np.matmul(key, matrix_mensaje)

        # Se obtiene el modulo sobre el diccionario de cada celda.
        cifrado = cifrado % 26

        # Se codifica de valores numéricos a los del diccionario, añadiendo a ciphertext el valor en el diccionario pasandole como indice la i posicion de la variable cifrado.
        for i in range(0, len(cifrado)):
            ciphertext += diccionario_decrypt[str(cifrado[i])]
    else:

    # Si el tamaño del mensaje es menor o igual al tamaño de la clave.

        # Si al dividir en trozos del tamaño de la clave, existe algun trozo que tiene menos caracteres que la long. de la clave se añaden tantas 'X' como falten.
        while len(message) % len(key) != 0:
            message = message + 'X'
            
        # Se divide el mensaje en subsstrings de tamaño len(key) y se almacenan como valores de un array.
        matrix_mensaje = [message[i:i + len(key)] for i in range(0,
                          len(message), len(key))]
        
        # Para cada valor del array (grupo de caracteres de la longitud de la clave).
        for bloque in matrix_mensaje:

            # Crear la matriz para el bloque.
            for i in range(0, len(bloque)):
                list_temp.append(diccionario_encryt[bloque[i]])

            # Se crea la matriz de ese bloque.
            matrix_encrypt = np.array(list_temp)

            # Se multiplica la matriz clave por la del bloque.
            cifrado = np.matmul(key, matrix_encrypt)

            # Se obtiene el modulo sobre el diccionario de cada celda.
            cifrado = cifrado % 26

            # Se codifica de valores numéricos a los del diccionario, añadiendo a ciphertext el valor en el diccionario pasándole como indice la i posición de la variable cifrado.
            for i in range(0, len(cifrado)):
                ciphertext_temp += diccionario_decrypt[str(cifrado[i])]

            # Se inicializan las variables para el siguiente nuevo bloque.
            matrix_encrypt = []
            list_temp = []

        ciphertext = ciphertext_temp

    return ciphertext

def hillDecipher(encrypted_text, key_matrix):
    """
    Función que descifra un mensaje cifrado utilizando el cifrado Hill.
    Devuelve el texto descifrado en base al mensaje cifrado y la clave proporcionada.

    Parámetros:
        encrypted_text : str
            El mensaje cifrado que se desea descifrar. El texto debe estar en mayúsculas y sin espacios.
        key_matrix : numpy.ndarray
            La matriz clave utilizada para el cifrado. Debe ser una matriz cuadrada (de tamaño n x n) y tener inversa modular en módulo 26.

    Retorna:
        str
            El texto descifrado.
    """

    # Calcular la matriz inversa de la clave, módulo 26
    key_matrix_inv = np.array(Matrix(key_matrix).inv_mod(26))

    # Dividir el texto cifrado en bloques del tamaño de la clave
    n = len(key_matrix)
    matrix_mensaje = [encrypted_text[i:i + n] for i in range(0, len(encrypted_text), n)]

    decrypted_text = ''

    for bloque in matrix_mensaje:
        # Convertir el bloque a una lista de números
        lista_numeros = [diccionario_encryt[char] for char in bloque]
        
        # Crear una matriz columna del bloque
        matriz_bloque = np.array(lista_numeros).reshape(-1, 1)
        
        # Multiplicar la matriz inversa por el bloque (mod 26)
        cifrado_descifrado = np.matmul(key_matrix_inv, matriz_bloque) % 26
        
        # Convertir el resultado de vuelta a texto
        for numero in cifrado_descifrado:
            decrypted_text += diccionario_decrypt[str(numero[0])]

    return decrypted_text

def opcion1():
    """
    Función para generar una matriz llave de tamaño n x n.
    Permite al usuario ingresar el tamaño de la matriz y genera una matriz de valores aleatorios en el rango [0, 25].

    Parámetros:
        Ninguno.

    Retorna:
        None.
        Imprime la matriz llave generada o mensajes de error en caso de entrada inválida.
    """

    try:
        size = int(input("\n[!] Introduce el tamaño n de la matriz llave (n x n): "))

        if size < 1:
            print("\n[!] El tamaño debe ser mayor o igual a 1.")
            return
                    
        key = hillGenKey(size)
        print("\n[+] Matriz llave generada:\n")
        print(key)

    except ValueError:
        print("\n[!] Entrada inválida. Por favor, ingrese un número entero.")

def opcion2():
    """
    Función para cifrar un mensaje utilizando el cifrado Hill.
    Permite elegir entre cifrar con una clave conocida o generar una clave aleatoria.

    Parámetros:
        Ninguno.

    Retorna:
        None.
        Imprime el mensaje cifrado o muestra mensajes de error en caso de fallos.
    """

    try:
        message = input("\n[!] Ingrese el mensaje a cifrar: ").upper().replace(" ", "")

        print("\n────────────────────────────────────────")
        print("============  Menú Cifrado  ============")
        print("────────────────────────────────────────")
        print(" 1. Cifrar mensaje con clave conocida.")
        print(" 2. Cifrar mensaje con clave aleatoria")
        print("────────────────────────────────────────\n")

        opcion = input("\n[!] Seleccione una opción: ")

        # Opción 1: Cifra mensaje con clave conocida.
        if opcion == '1':

            try:
                size = int(input("\n[!] Ingrese el tamaño n de la matriz llave (n x n): "))
                            
                if size < 1:
                    print("\n[!] El tamaño debe ser mayor o igual a 1.")
                    return
                            
                key = ingresarClave(size)

                ciphertext = hillCypher(message, key)
                print(f"\n[+] Mensaje cifrado: {ciphertext}")

            except ValueError:
                print("\n[!] Entrada inválida. Por favor, ingrese un número entero.")
        
        # Opción 2: Cifra mensaje con clave aleatoria.
        elif opcion == '2':

            try:
                size = int(input("\n[!] Ingrese el tamaño n de la matriz llave (n x n): "))
                key = hillGenKey(size)
                print(f"\n[+] Matriz llave generada automáticamente:\n{key}")
                            
                ciphertext = hillCypher(message, key)
                print(f"\n[+] Mensaje cifrado: {ciphertext}")

            except ValueError:
                print("\n[!] Entrada inválida. Por favor, ingrese un número entero.")

    except Exception as e:
        print(f"\n[!] Error al cifrar: {e}")

def opcion3():
    """
    Función para descifrar un mensaje cifrado utilizando el cifrado Hill.
    Pide al usuario ingresar el mensaje cifrado y la clave correspondiente.

    Parámetros:
        Ninguno.

    Retorna:
        None.
        Imprime el mensaje descifrado o muestra mensajes de error en caso de fallos.
    """

    try:
        ciphertext = input("\n[!] Ingrese el mensaje cifrado: ").upper().replace(" ", "")
        size = int(input("Ingrese el tamaño n de la matriz llave (n x n): "))

        key = ingresarClave(size)
       
        plaintext = hillDecipher(ciphertext, key)
        print(f"\n[+] Mensaje descifrado: {plaintext}")

    except Exception as e:
        print(f"\n[!] Error al descifrar: {e}")

def hill():
    """
    Función de menú interactivo para el cifrado Hill.
    Permite al usuario realizar las siguientes operaciones:
    
    Opciones:
        1. Generar Matriz Llave: Genera una matriz clave aleatoria para el cifrado.
        2. Cifrar Mensaje: Permite cifrar un mensaje usando una clave conocida o una generada aleatoriamente.
        3. Descifrar Mensaje: Descifra un mensaje cifrado utilizando una clave proporcionada.
           (Nota: Actualmente hay muchas veces que da el error "zero division".)
        4. Salir: Finaliza la ejecución del programa.
    
    Retorna:
        None.
    """

    while True:
        print("\n─────────────────────────────────────────")
        print("==============  Menú Hill  ==============")
        print("─────────────────────────────────────────\n")
        print(" 1. Generar Matriz Llave")
        print(" 2. Cifrar Mensaje")
        print(" 3. Descifrar Mensaje (A veces da error)")
        print("\n─────────────────────────────────────────")
        print(" 4. Salir")
        print("─────────────────────────────────────────\n")
        
        opcion = input("\n[!] Seleccione una opción: ")
        
        if opcion == '1':
            opcion1()
        
        elif opcion == '2':
            opcion2()
        
        elif opcion == '3':
            opcion3()
        
        elif opcion == '4':
            print("\n[!] Saliendo del programa...")
            break
        
        else:
            print("\n[!] Opción inválida. Por favor, seleccione una opción válida (1-4).")

if __name__ == "__main__":
    hill()
```