---
title: Códigos en python para el cifrado por Mochilas
author: Kesero
description: Códigos realizados en python para el cifrado por mochilas, mochilas trampa y criptoanálisis de Shamir y Zippel.
date: 2024-12-09 13:20:00 +0800
categories: [Criptografía, Códigos en python]
tags: [Mochilas Trampa, Mochilas, Códigos]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Mochilas/img/Titulo.png?raw=true
  lqip: 
  alt: 
comments: true
---

## Introducción

En este post, contaréis con las prácticas que he desarrollado en `python` sobre el `cifrado por mochilas` y `mochilas trampa`. Dichas prácticas se han desarrollado a partir de la relación de ejercicios impuestas por el profesor con el fin de guiar la implementación de cada función.

Es por ello que comparto con vosotros todos los códigos desarrollados para que le echéis un vistazo, además de compartiros los recursos teóricos utilizados con el fin de aprender lo necesario para comprender en su totalidad el funcionamiento de dichos cifrados.

## Recursos Teóricos

![Cap](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Teoria/Mochilas/img/Portada_teoria.png?raw=true)

En cuanto a teoría respecta, os dejo adjuntada la presentación utilizada para enteder y comprender el cifrado mediante mochilas en este [enlace](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Teoria/Mochilas/Mochilas.pdf).

## Relación de ejercicios

La relación de ejercicios utilizada para la realización de las prácticas es la siguiente.

![Relacion_1](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Mochilas/img/Practica_Mochilas-1.png?raw=true)

![Relacion_2](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Mochilas/img/Practica_Mochilas-2.png?raw=true)

## Ejercicios

Tendréis todos los códigos desarrollados en mi Github, más concretamente [aquí](https://github.com/k3sero/Blog_Content/tree/main/Criptografia/Codigos_Practicas/Mochilas).

Al final de los ejercicios, contaréis con el `menuMochilas` para comprobar de manera interactiva el cifrado y descifrado de ambos procedimientos. Recordad que necesitáis tener en local todos los archivos para poder ejecutar las funcionalidades de dicho menú.

### Ejercicio 1 (Texto a Número y Viceversa)

![Ejercicio](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Mochilas/img/ex1.png?raw=true)

```py
"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones del ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

def letter2ascii(char):
    """
    Convierte un carácter a su valor ASCII.

    Parámetros:
        char : str
            Un único carácter (string de longitud 1) que se desea convertir a su valor ASCII.

    Retorna:
        int
            El valor numérico ASCII correspondiente al carácter ingresado.
    """
    return ord(char)

def ascii2binary(ascii_value, n):
    """
    Convierte un valor ASCII a una lista de bits binarios de longitud n.
    
    Parámetros:
        ascii_value : int
            Valor ASCII a convertir.
        n : int
            Número de bits requeridos para la mochila.
    
    Retorna:
        list[int]
            Lista de bits de longitud n que representan el valor ASCII en binario.
    """
    # Comprobación de longitud.
    if len(char) != 1:
        raise ValueError("El valor debe ser una única letra o un solo carácter.")

    # Convertir a binario y ajustar la longitud al tamaño de la mochila.
    return [int(b) for b in f"{ascii_value:08b}"][-n:]

    # Permitir espacios u otros caracteres (en caso de que se quiera cifrar también caracteres especiales)
    if char == " ":
        return 32  # ASCII para espacio
    elif char.isalpha():  # Si es letra, convertir a mayúscula
        return ord(char.upper())
    else:
        return ord(char)  # Si es otro carácter, devolver su valor ASCII directamente

def ascii2letter(ascii_code):
    """
    Convierte un código ASCII (en el rango de 65 a 90) en una letra mayúscula.

    Esta función toma un valor ASCII correspondiente a una letra mayúscula y devuelve el carácter de esa letra.

    Parámetros:
        ascii_code : int
            Un valor ASCII entre 65 y 90 que representa una letra mayúscula.

    Retorna:
        str
            La letra correspondiente al valor ASCII proporcionado.
    """

    if not (65 <= ascii_code <= 90):
        raise ValueError("El valor ASCII debe corresponder a una letra mayúscula.")

    return chr(ascii_code)

def binary2ascii(binary_representation):
    """
    Convierte una lista de bits en binario a su carácter ASCII correspondiente.

    Esta función toma una lista de bits (0s y 1s) que representan un valor binario y lo convierte a su 
    valor ASCII correspondiente, devolviendo el carácter asociado.

    Parámetros:
        binary_representation : list
            Una lista de 8 elementos (0s y 1s) que representan un valor binario.

    Retorna:
        str
            El carácter ASCII correspondiente al valor binario dado.
    """

    # Convertir la lista de bits a una cadena binaria
    binary_string = ''.join(map(str, binary_representation))
    
    # Convertir la cadena binaria a un valor ASCII
    ascii_value = int(binary_string, 2)
    
    # Convertir el valor ASCII a su carácter correspondiente
    return chr(ascii_value)
```

### Ejercicio 2 (Funciones Mochilas)

![Ejercicio](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Mochilas/img/ex2.png?raw=true)

```py
"""
Nombre del archivo: ex2.py
Descripción: Este módulo contiene la funciones del ejercicio 2.
Autor: Carlos Marín Rodríguez
"""

from itertools import combinations
from ex1 import *

def knapsack(vector):
    """
    Determina el tipo de mochila en base a un vector de enteros.

    - Mochila Supercreciente: Cada elemento del vector es mayor que la suma de los anteriores. (1)
    - Mochila no supercreciente: Es una mochila, pero no cumple el criterio de supercreciente. (0)
    - No es mochila: Contiene elementos negativos o no es un vector con números enteros positivos. (-1)

    Parámetros:
        vector : list
            Una lista de números enteros, que representan los valores de los elementos de la mochila.

    Retorna:
        int
            - 1 si es una mochila supercreciente.
            - 0 si es una mochila pero no supercreciente.
            - -1 si no es una mochila (por contener elementos negativos o no ser un vector con enteros).
    """

    total = 0

    #Verificar si todos los elementos son enteros positivos.
    if not all(isinstance(x, int) and x > 0 for x in vector):
        return -1 # No es una mochila.
    
    # Comprobar si es una mochila.
    for num in vector:

        # Mochila pero no supercreciente.
        if num <= total:
            return 0 
        
        total += num
    
    # Mochila supercreciente.
    return 1

def knapsacksol(s, v):
    """
    Determina si el valor v puede obtenerse mediante una mochila supercreciente s.
    Devuelve los índices de los elementos que forman el valor objetivo v.

    Si la mochila s es supercreciente, utiliza un algoritmo eficiente basado en su propiedad.
    Si la mochila no es supercreciente, utiliza un algoritmo de fuerza bruta.

    Parámetros:
        s : list
            Una lista de enteros positivos que representan los elementos de la mochila.
            Debe ser una mochila, ya sea supercreciente o no.
        
        v : int
            El valor objetivo que se desea obtener con una combinación de los elementos de la mochila.

    Retorna:
        list
            Una lista con los índices de los elementos que suman el valor v, si se puede obtener dicho valor.
            Si no es posible obtener el valor v, devuelve None.
    """

    # Si la mochila es supercreciente, utilizamos su algoritmo.
    if knapsack(s) == 1:

        indices = []
        n = len(s)

        # Bucle for empezando en n-1, acaba en -1 y tiene un paso de -1.
        for i in range(n - 1, -1, -1):

            if s[i] <= v:
                indices.append(i)
                v -= s[i]

        return indices if v == 0 else None

    # Si la mochila no es supercreciente, usamos el algoritmo general.
    n = len(s)

    for r in range(1, n + 1):

        # Generamos con combinations todas las posibles combinaciones.
        for combination in combinations(range(n), r):
            subset_sum = sum(s[i] for i in combination)
            if subset_sum == v:
                return list(combination)

    # Si no se encuentra solución, no se alcanza el valor objetivo.
    return None

def knapsackcipher(text, knapsack):
    """
    Función que cifra un texto utilizando el cifrado por mochilas. 
    Realiza los pasos de conversión a ASCII, agrupación en bloques del tamaño de la mochila y
    realiza el cifrado con la suma ponderada.

    Parámetros:
    - text (str): Texto que se desea cifrar.
    - knapsack (list[int]): Mochila supercreciente utilizada para el cifrado.

    Retorno:
    - list[int]: Lista de números enteros que representan el texto cifrado.
    """

    ciphertext = []
    block_size = len(knapsack)  # Tamaño de los bloques (debe coincidir con el tamaño de la mochila)

    # Convertir cada carácter del texto a su representación ASCII y luego a binario (8 bits).
    binary_text = ''.join(f"{ord(char):08b}" for char in text)
    
    # Dividir el texto binario en bloques del tamaño de la mochila.
    blocks = [binary_text[i:i+block_size] for i in range(0, len(binary_text), block_size)]

    if len(blocks[-1]) < block_size:
        blocks[-1] = blocks[-1].ljust(block_size, '1')  # Como es un bloque corto, se rellena con 1 al final 

    # Cifrar cada bloque utilizando la mochila.
    for block in blocks:
        # Convertir el bloque binario en una lista de bits.
        bits = [int(bit) for bit in block]

        # Realizar la suma ponderada utilizando la mochila.
        cipher_value = sum(k * b for k, b in zip(knapsack, bits))

        # Añadir el valor cifrado a la lista de resultados.
        ciphertext.append(cipher_value)
    
    return ciphertext

def knapsackdecipher(ciphertext, knapsack):
    """
    Función que descifra un texto cifrado utilizando el cifrado por mochilas.

    Parámetros:
    - ciphertext (list[int]): Lista de números enteros que representan el texto cifrado.
    - knapsack (list[int]): Mochila supercreciente utilizada para el cifrado.

    Retorno:
    - plaintext (str): El texto descifrado.
    """

    n = len(knapsack)  # Tamaño de los bloques.
    plaintext_bits = []  # Almacenará todos los bits descifrados.
    plaintext = ""

    for value in ciphertext:
        # Reconstruir el bloque binario a partir del valor cifrado.
        binary_representation = [0] * n  # Inicializar lista binaria de tamaño n.
        for i in range(n - 1, -1, -1):  # Iterar desde el final de la mochila hacia el principio.
            if knapsack[i] <= value:
                binary_representation[i] = 1
                value -= knapsack[i]
        
        # Añadir los bits reconstruidos al texto descifrado.
        plaintext_bits.extend(binary_representation)

    # Agrupar los bits descifrados en bloques de 8 y convertirlos a caracteres ASCII.
    for i in range(0, len(plaintext_bits), 8):
        block = plaintext_bits[i:i+8]  # Tomar un bloque de 8 bits
        if len(block) < 8:  # Ignorar bloques incompletos
            break
        ascii_value = int(''.join(map(str, block)), 2)  # Convertir a número decimal
        plaintext += chr(ascii_value)  # Convertir a carácter ASCII

    return plaintext
```

### Ejercicio 3 (Funciones Mochilas Trampa)

![Ejercicio1](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Mochilas/img/ex3.png?raw=true)

![Ejercicio](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Mochilas/img/ex3_2.png?raw=true)

```py
"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3.
Autor: Carlos Marín Rodríguez
"""

from sympy import primefactors
import random

from ex1 import *
from ex2 import *

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

def invmod(p, n):
    """
    Calcula el inverso modular de un número p en un módulo n utilizando el algoritmo extendido de Euclides.
    Es decir, encuentra un número x tal que: p * x ≡ 1 (mod n).

    El algoritmo extendido de Euclides resuelve la ecuación de Bézout: gcd(p, n) = x * p + y * n, donde gcd(p, n) = 1,
    lo que significa que p y n son coprimos y tiene un inverso modular en n.

    Parámetros:
        p : int
            El número del cual se desea encontrar el inverso modular en el módulo n.
        
        n : int
            El módulo en el cual se calculará el inverso de p.

    Retorna:
        int
            El inverso modular de p en el módulo n. Si no existe, lanza una excepción.
    """

    # Comprobaciones (p y n enteros, n entero negativo, p entero positivo, gcd = 1)
    if not isinstance(p, int) or not isinstance(n, int):
        raise ValueError("[!] Los números deben ser enteros.")
    if n < 0:
        n = abs(n)
        print("[W] El valor n es negativo, se consideraŕa positivo.")
    if p < 0:
        print(f"[W] El número p es negativo, se calculará su correspondiente en el anillo.")
        p = p % n
        
    result = algeucl(p,n)
    if algeucl(p,n) != 1:
        return None
    
    # 1 = x * p + b * n (b lo despreciamos)
    
    # Guardamos el valor original de n.
    module = n

    # Inicializamos los coeficientes de la id. de Bezout (a*x + b*y).
    x0, x1 ,y0, y1 = 1, 0, 0, 1

    while n != 0:
        
        q = p // n
        r = p - n * q

        # Actualizamos coeficientes x usando la relación del Algoritmo de Euclides.
        x_temp = x1
        x1 = x0 - q * x1
        x0 = x_temp

        # Actualizamos los coeficientes de y.
        y_temp = y1
        y1 = y0 - q * y1
        y0 = y_temp

        # Preparamos los valores para la próxima iteración.
        p = n
        n = r

    # Si obtenemos un inverso modular negativo, lo calculamos en el anillo.
    x0 = x0 % module

    return x0 # Inverso de p.

def checkwm(w,m,s):
    """
    Verifica si el valor w y el módulo m cumplen las condiciones necesarias para ser utilizados en una mochila trampa.

    - Verifica que w sea invertible módulo m.
    - Comprueba que no existan factores primos comunes entre w y al menos un elemento de s.

    Parámetros:
        w : int
            El número que debe ser invertible en el módulo m.
        
        m : int
            El módulo en el cual se comprobará si w tiene inverso.
        
        s : list of int
            Una lista de elementos con los cuales se comprobará si w tiene factores primos comunes.

    Retorna:
        bool
            True si w es válido para ser utilizado en una mochila trampa, es decir, si:
            - w es invertible módulo m
            - w no tiene factores primos comunes con ningún elemento de s.
            False si alguna de las condiciones no se cumple.
    """

    try:
        # Verifica si w es invertible módulo m.
        invmod(w, m)  # Si no lanza excepción, es invertible.
        
        if commonfactors(w, s):
            return False  # w tiene factores primos comunes con al menos un elemento de s.

        return True  # w es válido.
    except ValueError as e:
        print(f"\n[!] Error en la validación de w: {e}")
        return False

def commonfactors(w,s):
    """
    Comprueba si el número w tiene factores primos comunes con algún elemento de la mochila supercreciente s.

    La función calcula los factores primos de w y los compara con los factores primos de cada elemento de la lista s.
    Si hay factores primos comunes entre w y algún elemento de s, la función devuelve `True`.

    Parámetros:
        w : int
            El número con el cual se comprobarán los factores primos comunes.
        
        s : list of int
            Una lista de elementos de la mochila supercreciente, con los cuales se verifican los factores comunes con w.

    Retorna:
        bool
            True si w tiene factores primos comunes con algún elemento de la lista s.
            False si no tiene factores comunes con ningún elemento de la lista s.
    """

    factors_w = set(primefactors(w))
    
    # Verificar factores primos comunes con cada elemento de s.
    for element in s:
        factors_s = set(primefactors(element))
        if factors_w & factors_s:  # Intersección no vacía significa factores comunes.
            return True
    
    return False

def knapsackpublicandprivate(s):
    """
    Genera un par de claves pública y privada en base a una mochila supercreciente.

    La clave pública es una mochila trampa generada a partir de la mochila supercreciente proporcionada,
    mientras que la clave privada consiste en los parámetros w, m y la mochila supercreciente `s`.

    Parámetros:
        s : list of int
            La mochila supercreciente utilizada para generar las claves.

    Retorna:
        tuple
            Una tupla con la clave pública (mochila trampa) y la clave privada (w, m, mochila supercreciente).
            La clave pública es una lista de números generada a partir de la mochila supercreciente y el valor de w.
            La clave privada contiene los valores de w, m y la mochila supercreciente original.
    """

    # Verificar que s es una mochila supercreciente.
    if knapsack(s) != 1:
        raise ValueError("[!] La mochila proporcionada no es supercreciente.")

    # Calcular el valor mínimo de m (tiene que ser mayor o igual a 2 * a_n).
    an = s[-1]
    m_min = 2 * an

    print(f"\n[!] Introduce un valor del módulo m.")

    while True:
        try:
            m = int(input(f"El valor de m debe ser mayor o igual a {m_min} (2 * {an}): "))
            if m >= m_min:
                break
            print(f"[!] El valor de m debe ser al menos {m_min}.")
        except ValueError:
            print("[!] Introduce un valor entero válido para m.")

    # Buscar w.
    while True:
        try:

            print("\n[!] Introduce el valor de w.\n")
            print("────────────────────────────────────────────────\n")
            print("  1. Buscar W de forma aleatoria.")
            print("  2. Buscar w en un rango dado.")
            print("  3. Introduce un valor en concreto.")
            print("\n────────────────────────────────────────────────\n")
            choice = input("\n[!] Elige una opción: ").strip()
            
            if choice == "1":
                # Generar w de forma aleatoria y comprueba si es buen candidato.
                w = random.randint(2, m - 1)
                while not checkwm(w, m, s):
                    w = random.randint(2, m - 1)

                print(f"\n[+] Valor escogido aleatoriamente: {w}")

            elif choice == "2":
                # Generar w mediante rangos de forma aleatoria.
                lower = int(input("\n[!] Introduce el límite inferior del rango para w: "))
                upper = int(input("[!] Introduce el límite superior del rango para w: "))
                if lower < 2 or upper >= m:
                    print(f"\n[!] El rango debe estar entre 2 y {m-1}.")
                    continue

                if lower >= upper:
                    print("\n [!] El límite inferior debe ser menor que el límite superior.")
                    continue
        
                # Generar un valor aleatorio de w en el rango definido por el usuario.
                w = random.randint(lower, upper)

                # Se generan valores hasta conseguir uno candidato.
                while not checkwm(w, m, s):
                    w = random.randint(lower, upper-1)
                print(f"\n [+] Se ha seleccionado aleatoriamente w = {w} dentro del rango [{lower}, {upper}].")
    
            # Establece un w en concreto.
            elif choice == "3":
                w = int(input("\n[!] Introduce el valor para w: "))

            else:
                print("\n[!] Opción inválida.")
                continue

            # Verificar si w es adecuado
            if checkwm(w, m, s):
                break
            print("\n[!] El valor de w no es válido. Pruebe de nuevo con otro valor.")
        except ValueError:
            print("\n[!] Introduce valores válidos para w y el rango.")

    # Generar la mochila trampa (clave pública).
    public_key = [(w * element) % m for element in s]

    # Retornar claves pública y privada.
    return public_key, (w, m, s)

def knapsackdeciphermh(s, m, w, ciphertext):
    """
    Descifra un mensaje cifrado utilizando el cifrado por mochila supercreciente.

    La función utiliza la mochila supercreciente y los parámetros w (clave privada) y m (módulo) 
    para descifrar un mensaje previamente cifrado con el cifrado de mochila.

    Parámetros:
        s : list of int
            La mochila supercreciente utilizada en el cifrado.
        m : int
            El valor del módulo utilizado para el cifrado.
        w : int
            El valor de la clave privada (w) utilizada en el cifrado.
        ciphertext : list of int
            El mensaje cifrado representado por una lista de números.

    Retorna:
        str
            El mensaje descifrado como una cadena de texto.
    """

    w_inv = invmod(w, m)
    plaintext_bits = []

    # Descifrar cada valor en el criptograma.
    for value in ciphertext:
        # Convertir el valor cifrado al espacio de la mochila supercreciente.
        transformed_value = (value * w_inv) % m

        # Obtener la representación binaria usando la mochila supercreciente.
        binary_representation = [0] * len(s)

        # Resolver la mochila supercreciente para el valor transformado.
        for i in range(len(s) - 1, -1, -1):
            if s[i] <= transformed_value:
                binary_representation[i] = 1
                transformed_value -= s[i]

        # Añadir los bits reconstruidos al texto descifrado.
        plaintext_bits.extend(binary_representation)

        # Agrupar los bits descifrados en bloques de 8 y convertirlos a caracteres ASCII.
        plaintext = ""
        for i in range(0, len(plaintext_bits), 8):
            block = plaintext_bits[i:i+8]  # Tomar un bloque de 8 bits.
            if len(block) < 8:  # Ignorar bloques incompletos.
                break
            ascii_value = int(''.join(map(str, block)), 2)  # Convertir a número decimal.
            plaintext += chr(ascii_value)  # Convertir a carácter ASCII.

    return plaintext
```

### Ejercicio 4 (Criptoanálisis Shamir y Zippel)

![Ejercicio](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/Mochilas/img/ex4.png?raw=true)

```py
"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funcion de cryptoanálisis del ejercicio 4.
Autor: Carlos Marín Rodríguez
"""

from ex1 import *
from ex2 import *
from ex3 import * 

import time

def cryptoanalysis(b, m):
    """
    Criptoanálisis de la mochila de Merkle-Hellman utilizando el ataque de Shamir y Zippel.
    Este método buscará la mochila supercreciente en distintos rangos.
    
    Parámetros:
        b : list of int
            La clave pública de la mochila difícil (b1, b2, ..., bn).
        m : int
            El módulo de la mochila difícil.
    
    Retorna:
        list of int
            La mochila supercreciente generada a partir del ataque.
    """

    print(f"\n[+] Iniciando criptoanálisis de Shamir y Zippel...\n")

    start_time = time.time()  # Iniciar medición del tiempo.

    n = len(b)  # Número de elementos en la clave pública.
    b1, b2 = b[0], b[1]

    # Paso 1: Calcular b2^(-1) mod m.
    b2_inv = invmod(b2, m)

    if b2_inv is None:
        print("[!] Error: No existe el inverso de b2 en el módulo m.")
        return None

    # Paso 2: Calcular q = b1 * b2^(-1) mod m.
    q = (b1 * b2_inv) % m

    # Paso 3: Generar los primeros {q, 2q, ..., (2^n+1)* q mod m}.
    multiples_q = [(q * i) % m for i in range(1, 2 ** (n + 1) + 1)]
    multiples_q = [x for x in multiples_q if x != 0]  # Filtrar los ceros

    # Criptoanálisis iterativo.
    rango_inicial = 1  # El rango inicial de búsqueda de q.
    rango_final = 2 ** (n + 1)  # El rango final.
    while multiples_q:
        print(f"[!] Intentando con el rango [{rango_inicial}, {rango_final}]...")

        # Empezar medición del tiempo para este rango.
        rango_start_time = time.time()

        # Paso 4: Seleccionar el valor más pequeño como candidato para a1.
        candidate_a1 = min(multiples_q)

        # Paso 5: Calcular w = b1 * a1^(-1) mod m.
        a1_inv = invmod(candidate_a1, m)

        if a1_inv is None:
            print(f"[!] Inverso de {candidate_a1} no encontrado. Continuando con el siguiente.")
            multiples_q.remove(candidate_a1)
            continue

        w = (b1 * a1_inv) % m

        # Calculamos el inverso de w.
        w_inv = invmod(w, m)

        # Paso 6: Calcular los elementos de la mochila supercreciente a_i.
        a = [(w_inv * b_i) % m for b_i in b]

        # Verificar si la mochila es supercreciente.
        if knapsack(a):
            # Mochila supercreciente encontrada.
            print(f"\n[+] Tiempo requerido en este rango: {time.time() - rango_start_time:.2f} segundos")
            print(f"[+] Mochila supercreciente encontrada: {a}")
            return a

        # Si no se encontró solución, eliminamos el candidato y seguimos.
        multiples_q.remove(candidate_a1)

        # Preguntar al usuario si desea continuar con el siguiente rango.
        if not multiples_q:
            print(f"\n[!] No se ha encontrado solución en este rango.")
            continue_choice = input(f"¿Desea continuar con el siguiente rango? (si/no): ").lower()
            if continue_choice != 'si':
                break
            else:
                rango_inicial = rango_final + 1
                rango_final = rango_inicial * 2
                multiples_q = [(q * i) % m for i in range(rango_inicial, rango_final + 1)]
                multiples_q = [x for x in multiples_q if x != 0]

    print(f"\n[!] Criptoanálisis finalizado. No se encontró solución.")

    return None
```

### Menu Mochilas

Finalmente el menú que integra todas la funcionalidades anteriores es el siguiente.

```py
"""
Nombre del archivo: menuMochilas.py
Descripción: Este módulo contiene el menú interactivo para la práctica de mochilas.
Autor: Carlos Marín Rodríguez
"""

from ex1 import *
from ex2 import *
from ex3 import *
from ex4 import *

def menuMochilas():
    """
    Presenta un menú interactivo para gestionar opciones relacionadas con mochilas.

    Opciones del menú:
        1. Menú mochilas normales.
        2. Menú mochilas trampa.
        3. Criptoanálisis Shamir y Zippel.
        4. Salir del menú.

    Esta función permite al usuario seleccionar una opción y ejecuta la correspondiente
    función asociada. Maneja entradas inválidas y errores durante la ejecución.

    Parámetros:
        Ninguno

    Retorna:
        None
    """

    salir = False

    while not salir:
        print("\n─────────────────────────────────────────────────")
        print("================  Menú Mochilas  ================")
        print("─────────────────────────────────────────────────\n")
        print("  1. Menú mochilas.")
        print("  2. Menú mochilas trampa.")
        print("  3. Criptoanálisis Shamir y Zippel.")
        print("\n─────────────────────────────────────────────────")
        print("  4. Salir")
        print("─────────────────────────────────────────────────")
        opcion = input("\n[!] Elige una opción: ").strip()

        try:
            # Opción 1: Menú mochilas normales.
            if opcion == '1':
                opcion1()
                
            # Opción 2: Menú mochilas trampa.
            elif opcion == '2':
                opcion2()
  
            # Opción 3: Criptoanálisis Shamir y Zippel.
            elif opcion == '3':
                opcion3()

            # Opción 4: Salir.
            elif opcion == '4':
                salir = True
                print("\n[!] Saliendo del menú...")
                return    

            else:
                # Opción no válida.
                print("[!] Opción no válida. Por favor, intente de nuevo.")

        except ValueError as ve:
            print(f"[!] Error de entrada: {ve}")
        except Exception as e:
            print(f"[!] Ha ocurrido un error: {e}")

        print()  # \n.

def opcion1():
    """
    Submenú para cifrar o descifrar mensajes utilizando una mochila dada.

    Opciones del submenú:
        1. Cifrar mensaje: Solicita un texto y una mochila para cifrar el mensaje.
        2. Descifrar mensaje: Solicita un mensaje cifrado y la mochila correspondiente para descifrarlo.
        3. Atrás: Regresa al menú principal.

    Parámetros:
        Ninguno

    Retorna:
        None
    """
    print("\n\n────────────────────────────────────────────────")
    print("=============  Funciones Mochilas  =============")
    print("────────────────────────────────────────────────\n")
    print("  1. Cifrar mensaje.")
    print("  2. Descifrar un mensaje.")
    print("\n────────────────────────────────────────────────")
    print("  3. Atrás.")
    print("────────────────────────────────────────────────\n")
    op = input("\n[!] Elige una opción: ").strip()

    try:
        # Opción 1: Cifrar un mensaje con una mochila dada.
        if op == '1':

            s = []
            text = ""

            #Pedimos el texto a el usuario.
            text = input("\n[!] Introduce el texto que quieres cifrar: ").strip()
        
            # Pedir la mochila al usuario.
            mochila_input = input("\n[!] Introduce la mochila a utilizar (Ej: 2, 3, 6, 13, 27, 52, 105, 210): ").strip()
            # Convertir la entrada en una lista de enteros.
            s = [int(x) for x in mochila_input.split(",")]

            # Comprobamos la mochila introducida.
            mochila_tipo = knapsack(s)
            if mochila_tipo == 1:
                print("\n[+] La mochila es supercreciente, se procederá con el cifrado.")
            elif mochila_tipo == 0:
                print("\n[+] La mochila no es supercreciente, se procederá con el cifrado igualmente.")
            elif mochila_tipo == -1:
                print("\n[!] Los elementos introducidos no forman una mochila.")
                return

            # Ciframos el mensaje.
            encrypted = knapsackcipher(text, s)
            print(f"\n[+] El mensaje cifrado es: {encrypted}")

        # Opcion 2: Descfirar mediante una mochila dada.
        if op == '2':

            s = []
            encypted = []

            # Pedir el texto encriptado.
            encrypted_raw = input("\n[!] Introduce el texto encriptado previamente (Ej: 9, 3, 0, 5, 11): ").strip()
            # Convertir la entrada en una lista de enteros.
            encrypted = [int(x) for x in encrypted_raw.split(",")]

            # Pedir la mochila al usuario.
            mochila_input = input("\n[!] Introduce la mochila a utilizada en el cifrado (Ej: 2, 3, 6, 13, 27, 52, 105, 210): ").strip()
            # Convertir la entrada en una lista de enteros.
            s = [int(x) for x in mochila_input.split(",")]

            mochila_tipo = knapsack(s)
            if mochila_tipo == 1:
                print("\n[+] La mochila es supercreciente, se procederá con el cifrado.")
            elif mochila_tipo == 0:
                print("\n[+] La mochila no es supercreciente, se procederá con el cifrado igualmente.")
            elif mochila_tipo == -1:
                print("\n[!] Los elementos introducidos no forman una mochila.")
                return

            # Ciframos el mensaje
            plaintext = knapsackdecipher(encrypted, s)

            print(f"\n[+] El mensaje descifrado es {plaintext}")

        # Opción 3: atrás.
        if op == '3':
            return

    except ValueError as ve:
        print(f"\n[!] Error de entrada: {ve}")
    except Exception as e:
        print(f"\n[!] Ha ocurrido un error: {e}")

def opcion2():
    """
    Submenú para cifrar o descifrar mensajes utilizando mochilas trampa.

    Opciones del submenú:
        1. Cifrar mensaje con mochilas trampa: Solicita un texto y una mochila supercreciente para cifrar el mensaje utilizando una clave pública.
        2. Descifrar mensaje con mochilas trampa: Solicita un mensaje cifrado y la mochila supercreciente correspondiente junto con los parámetros privados para descifrarlo.
        3. Atrás: Regresa al menú principal.

    Parámetros:
        Ninguno

    Retorna:
        None
    """

    print("\n\n────────────────────────────────────────────────")
    print("============  Funciones Mochilas T  ============")
    print("────────────────────────────────────────────────\n")
    print("  1. Cifrar mensaje con mochilas trampa.")
    print("  2. Descifrar un mensaje con mochilas trampa")
    print("\n────────────────────────────────────────────────")
    print("  3. Atrás.")
    print("────────────────────────────────────────────────\n")
    op = input("\n[!] Elige una opción: ").strip()

    try:
        # Opción 1: Cifrar un mensaje con una mochila supercreciente (mochila trampa).
        if op == '1':

            s = []
            text = ""

            #Pedimos el texto a el usuario.
            text = input("\n[!] Introduce el texto que quieres cifrar: ").strip()
        
            # Pedir la mochila al usuario.
            mochila_input = input("\n[!] Introduce la mochila supercreciente a utilizar (Ej: 2, 3, 6, 13, 27, 52, 105, 210): ").strip()
            # Convertir la entrada en una lista de enteros.
            s = [int(x) for x in mochila_input.split(",")]

            mochila_tipo = knapsack(s)
            if mochila_tipo == -1:
                print("\n[!] Los elementos introducidos no forman una mochila.")
                return
            elif mochila_tipo == 0:
                print("\n[!] La mochila no es supercreciente, debe serlo para proceder con el cifrado.")
                return

            print("\n[+] La mochila es supercreciente, se procederá con el cifrado.")

            public_key, (w, m, s_temp) = knapsackpublicandprivate(s)

            # Resultados
            print("\n[+] Clave pública (mochila trampa):", public_key)
            print("[+] Clave privada (w, m, mochila supercreciente):", (w, m, s))

            # Cifrar el mensaje
            encrypted = knapsackcipher(text, public_key)

            print(f"\n[+] El mensaje cifrado es: {encrypted}")


        # Opcion 2: Descfirar mediante una mochila dada.
        if op == '2':

            s = []
            encypted = []

            # Pedir el texto encryptado
            encrypted_raw = input("\n[!] Introduce el texto encriptado previamente (Ej: 9, 3, 0, 5, 11): ").strip()
            # Convertir la entrada en una lista de enteros.
            encrypted = [int(x) for x in encrypted_raw.split(",")]


            # Pedir la mochila al usuario.
            mochila_input = input("\n[!] Introduce la mochila supercreciente utilizada (Ej: 2, 3, 6, 13, 27, 52, 105, 210): ").strip()
            # Convertir la entrada en una lista de enteros.
            s = [int(x) for x in mochila_input.split(",")]
            
            m = int(input("\n[!] Introduce el valor del módulo m utilizado: "))
            w = int(input("[!] Introduce el valor de w utilizado: "))

            mochila_tipo = knapsack(s)
            if mochila_tipo == -1:
                print("\n[!] Los elementos introducidos no forman una mochila.")
                return
            elif mochila_tipo == 0:
                print("\n[!] La mochila no es supercreciente, inserte una nueva mochila.")
                return            

            print("\n[+] La mochila es supercreciente, se procederá con el cifrado.")
            
            # Desciframos el mensaje
            plaintext = knapsackdeciphermh(s, m, w, encrypted)
            print(f"\n[+] El mensaje descifrado es: {plaintext}")

        if op == '3':
            return

    except ValueError as ve:
        print(f"\n[!] Error de entrada: {ve}")
    except Exception as e:
        print(f"\n[!] Ha ocurrido un error: {e}")

def opcion3():
    """
    Realiza el criptoanálisis de Shamir y Zippel con una mochila trampa dada utilizando el valor del módulo proporcionado.

    La función solicita al usuario una mochila trampa y un valor de módulo para intentar romper el cifrado utilizando un algoritmo de criptoanálisis.

    Parámetros:
        Ninguno

    Retorna:
        None
    """

    # Pedir la mochila al usuario.
    mochila_input = input("\n[!] Introduce la mochila trampa a romper (Ej: 3241, 572, 2163, 1256, 3531): ").strip()
    # Convertir la entrada en una lista de enteros.
    b = [int(x) for x in mochila_input.split(",")]

    mochila_tipo = knapsack(b)
    if mochila_tipo == -1:
        print("\n[!] Los elementos introducidos no forman una mochila.")
        return

    m = int(input("\n[!] Introduce el módulo asociado (Ej: 4089): "))

    cryptoanalysis(b, m)

if __name__ == "__main__":
    menuMochilas()
```